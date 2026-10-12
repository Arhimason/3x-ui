package service

import (
	"encoding/json"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"
)

// A vk-turn-proxy client and its mirrored wireguard peer share one ClientRecord
// and one client_traffics row by email. Every write from the wireguard side runs
// SyncInbound, which applies quota/expiry/subId unconditionally, so the mirrored
// peer must carry the vk-turn client's account or later wireguard writes wipe it.
func TestVKTurnClientAccountSurvivesWireguardWrites(t *testing.T) {
	setupConflictDB(t)
	db := database.GetDB()
	svc := &InboundService{}

	wgSettings, _ := json.Marshal(map[string]any{
		"mtu":       1420,
		"secretKey": "iLZqxL6Tn1Qe3jBJ7Bz1ULbpAFvWPLnGz0kSV0Zd2A=",
		"clients": []map[string]any{{
			"email": "wg-own", "privateKey": "aGVsbG8=", "publicKey": "pub-own",
			"allowedIPs": []string{"10.0.0.2/32"}, "enable": true, "subId": "sub-own",
		}},
	})
	wg := &model.Inbound{Tag: "wg-shared", Enable: true, Listen: "0.0.0.0", Port: 51830, Protocol: model.WireGuard, Settings: string(wgSettings)}
	if _, _, err := svc.AddInbound(wg); err != nil {
		t.Fatalf("add wg: %v", err)
	}
	vkSettings, _ := json.Marshal(map[string]any{
		"forward": map[string]any{"type": "wireguardInbound", "wireguardInboundId": wg.Id},
		"link":    "https://vk.com/call/join/test",
		"clients": []any{},
	})
	vk := &model.Inbound{Tag: "vk-shared", Enable: true, Listen: "0.0.0.0", Port: 56000, Protocol: model.VKTurnProxy, Settings: string(vkSettings)}
	if _, _, err := svc.AddInbound(vk); err != nil {
		t.Fatalf("add vk: %v", err)
	}

	const total = int64(10 << 30)
	const expiry = int64(1893456000000)
	alice := &VKTurnProxyClient{Email: "alice-vk", Enable: true, TotalGB: total, ExpiryTime: expiry, SubID: "sub-alice", LimitIP: 2, Comment: "paid"}
	if _, _, err := svc.AddVKTurnProxyClientDirect(vk.Id, alice, "example.com"); err != nil {
		t.Fatalf("add alice: %v", err)
	}

	check := func(stage string) {
		t.Helper()
		var rec model.ClientRecord
		if err := db.Where("email = ?", "alice-vk").First(&rec).Error; err != nil {
			t.Fatalf("[%s] ClientRecord: %v", stage, err)
		}
		if rec.TotalGB != total || rec.ExpiryTime != expiry || rec.SubID != "sub-alice" || rec.LimitIP != 2 || rec.Comment != "paid" {
			t.Errorf("[%s] ClientRecord total=%d expiry=%d subId=%q limitIp=%d comment=%q, want the vk-turn client's account",
				stage, rec.TotalGB, rec.ExpiryTime, rec.SubID, rec.LimitIP, rec.Comment)
		}
		var tr xray.ClientTraffic
		if err := db.Where("email = ?", "alice-vk").First(&tr).Error; err != nil {
			t.Fatalf("[%s] client_traffics: %v", stage, err)
		}
		if tr.Total != total || tr.ExpiryTime != expiry {
			t.Errorf("[%s] client_traffics total=%d expiry=%d, want %d/%d (quota would stop being enforced)", stage, tr.Total, tr.ExpiryTime, total, expiry)
		}
	}
	check("after add")

	if _, _, err := svc.AddVKTurnProxyClientDirect(vk.Id, &VKTurnProxyClient{Email: "bob-vk", Enable: true}, "example.com"); err != nil {
		t.Fatalf("add bob: %v", err)
	}
	check("after second vk client")

	cur, err := svc.GetInbound(wg.Id)
	if err != nil {
		t.Fatalf("get wg: %v", err)
	}
	if _, _, err := svc.UpdateInbound(cur); err != nil {
		t.Fatalf("resave wg: %v", err)
	}
	check("after wireguard resave")

	if err := svc.ReconcileVKTurnProxyClientPeers(); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	check("after reconcile")

	var own model.ClientRecord
	if err := db.Where("email = ?", "wg-own").First(&own).Error; err != nil || own.SubID != "sub-own" {
		t.Errorf("unrelated wireguard client changed: subId=%q err=%v", own.SubID, err)
	}
}

// Editing a vk-turn client's quota out of band leaves the mirrored wireguard row
// stale; the reconcile loop must bring it back in line.
func TestReconcileRefreshesDriftedMirroredAccount(t *testing.T) {
	stored := map[string]any{"enable": true, "limitIp": float64(0), "totalGB": float64(0), "expiryTime": float64(0), "tgId": float64(0), "subId": "x", "comment": "", "reset": float64(0)}
	client := &VKTurnProxyClient{Enable: true, SubID: "x"}
	if !accountMatches(stored, vkTurnProxyClientAccount(client)) {
		t.Fatal("identical account must match across JSON number decoding")
	}
	client.TotalGB = 5
	if accountMatches(stored, vkTurnProxyClientAccount(client)) {
		t.Fatal("changed quota must be detected as drift")
	}
}
