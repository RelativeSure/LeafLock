package services

import (
	"context"
	"testing"
	"time"

	miniredis "github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newTestShareLinkService(t *testing.T) (*ShareLinkService, *miniredis.Miniredis) {
	minidb := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: minidb.Addr()})
	return NewShareLinkService(client), minidb
}

func TestGenerateToken(t *testing.T) {
	seen := make(map[string]struct{})
	for i := 0; i < 5; i++ {
		token, err := GenerateToken()
		if err != nil {
			t.Fatalf("GenerateToken returned error: %v", err)
		}
		if len(token) == 0 {
			t.Fatalf("expected non-empty token")
		}
		if _, exists := seen[token]; exists {
			t.Fatalf("token should be unique, saw duplicate %q", token)
		}
		seen[token] = struct{}{}
	}
}

func TestShareLinkCacheLifecycle(t *testing.T) {
	service, minidb := newTestShareLinkService(t)
	ctx := context.Background()
	token := "abc123"
	cache := ShareLinkCache{
		NoteID:     "note-1",
		Permission: "read",
		ExpiresAt:  time.Now().Add(time.Hour),
		MaxUses:    5,
	}

	if err := service.CacheShareLink(ctx, token, cache); err != nil {
		t.Fatalf("CacheShareLink returned error: %v", err)
	}

	stored, err := service.GetShareLink(ctx, token)
	if err != nil {
		t.Fatalf("GetShareLink returned error: %v", err)
	}
	if stored == nil || stored.NoteID != cache.NoteID {
		t.Fatalf("expected cached note to be returned")
	}

	if err := service.IncrementUseCount(ctx, token); err != nil {
		t.Fatalf("IncrementUseCount returned error: %v", err)
	}

	updated, err := service.GetShareLink(ctx, token)
	if err != nil {
		t.Fatalf("GetShareLink after increment returned error: %v", err)
	}
	if updated.UseCount != 1 {
		t.Fatalf("expected use count 1, got %d", updated.UseCount)
	}

	if err := service.InvalidateShareLink(ctx, token); err != nil {
		t.Fatalf("InvalidateShareLink returned error: %v", err)
	}

	result, err := service.GetShareLink(ctx, token)
	if err != nil {
		t.Fatalf("GetShareLink after invalidate returned error: %v", err)
	}
	if result != nil {
		t.Fatalf("expected share link to be removed after invalidate")
	}

	if _, err := minidb.Get("share_link:" + token); err == nil {
		t.Fatalf("expected key to be deleted from redis")
	}
}

func TestInvalidateNoteShareLinks(t *testing.T) {
	service, minidb := newTestShareLinkService(t)
	ctx := context.Background()

	entries := map[string]ShareLinkCache{
		"token1": {NoteID: "note-a", Permission: "read"},
		"token2": {NoteID: "note-b", Permission: "write"},
		"token3": {NoteID: "note-a", Permission: "write"},
	}
	for token, data := range entries {
		if err := service.CacheShareLink(ctx, token, data); err != nil {
			t.Fatalf("failed to cache %s: %v", token, err)
		}
	}

	if err := service.InvalidateNoteShareLinks(ctx, "note-a"); err != nil {
		t.Fatalf("InvalidateNoteShareLinks returned error: %v", err)
	}

	if minidb.Exists("share_link:token1") || minidb.Exists("share_link:token3") {
		t.Fatalf("expected note-a share links to be removed")
	}
	if !minidb.Exists("share_link:token2") {
		t.Fatalf("expected share_link:token2 to remain")
	}
}

func TestRefreshTTL(t *testing.T) {
	service, minidb := newTestShareLinkService(t)
	ctx := context.Background()

	cache := ShareLinkCache{NoteID: "note", Permission: "read"}
	token := "refresh"
	if err := service.CacheShareLink(ctx, token, cache); err != nil {
		t.Fatalf("CacheShareLink returned error: %v", err)
	}

	if err := service.RefreshTTL(ctx, token); err != nil {
		t.Fatalf("RefreshTTL returned error: %v", err)
	}

	ttl := minidb.TTL("share_link:" + token)
	if ttl <= 0 {
		t.Fatalf("expected refreshed TTL to be positive, got %v", ttl)
	}
}
