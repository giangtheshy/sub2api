package service

import (
	"testing"

	"github.com/gin-gonic/gin"
)

func TestDetectAnthropicRefusalJSON(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		want    bool
	}{
		{"refusal", `{"type":"message","stop_reason":"refusal","content":[]}`, true},
		{"end_turn soft", `{"type":"message","stop_reason":"end_turn","content":[{"type":"text","text":"I can't help with that."}]}`, false},
		{"max_tokens", `{"stop_reason":"max_tokens"}`, false},
		{"empty", ``, false},
		{"garbage", `not json`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := DetectAnthropicRefusalJSON([]byte(tc.payload))
			if got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}

func TestDetectAnthropicPermissionError(t *testing.T) {
	ok, msg := DetectAnthropicPermissionError(403, []byte(`{"type":"error","error":{"type":"permission_error","message":"blocked"}}`))
	if !ok {
		t.Fatal("expected permission_error detected")
	}
	if msg != "blocked" {
		t.Fatalf("expected message blocked, got %q", msg)
	}
	if bad, _ := DetectAnthropicPermissionError(403, []byte(`{"error":{"type":"rate_limit_error"}}`)); bad {
		t.Fatal("rate_limit must not be permission_error")
	}
	if bad, _ := DetectAnthropicPermissionError(200, []byte(`{"error":{"type":"permission_error"}}`)); bad {
		t.Fatal("200 must not count")
	}
	if bad, _ := DetectAnthropicPermissionError(403, []byte(`not json`)); bad {
		t.Fatal("garbage must not count")
	}
}

func TestDetectAnthropicRefusalSSEDelta(t *testing.T) {
	ev := map[string]any{"type": "message_delta", "delta": map[string]any{"stop_reason": "refusal"}}
	if !DetectAnthropicRefusalSSEDelta(ev) {
		t.Fatal("expected refusal delta detected")
	}
	ev2 := map[string]any{"type": "message_delta", "delta": map[string]any{"stop_reason": "end_turn"}}
	if DetectAnthropicRefusalSSEDelta(ev2) {
		t.Fatal("end_turn must not detect")
	}
	if DetectAnthropicRefusalSSEDelta(map[string]any{"type": "message_delta"}) {
		t.Fatal("missing delta must not detect")
	}
	if DetectAnthropicRefusalSSEDelta(nil) {
		t.Fatal("nil event must not detect")
	}
}

func TestAnthropicRefusalMarkLifecycle(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(nil)

	if GetAnthropicRefusalMark(c) != nil {
		t.Fatal("expected no mark initially")
	}

	MarkAnthropicRefusal(c, AnthropicRefusalMark{Signal: AnthropicRefusalSignalRefusal, UpstreamStatus: 200})
	mark := GetAnthropicRefusalMark(c)
	if mark == nil || mark.Signal != AnthropicRefusalSignalRefusal {
		t.Fatalf("expected refusal mark, got %+v", mark)
	}

	// first-write-wins
	MarkAnthropicRefusal(c, AnthropicRefusalMark{Signal: AnthropicRefusalSignalPermissionError, UpstreamStatus: 403})
	if got := GetAnthropicRefusalMark(c); got.Signal != AnthropicRefusalSignalRefusal {
		t.Fatalf("expected first write to win, got %q", got.Signal)
	}

	ClearAnthropicRefusalMark(c)
	if GetAnthropicRefusalMark(c) != nil {
		t.Fatal("expected mark cleared")
	}

	// nil context must not panic
	MarkAnthropicRefusal(nil, AnthropicRefusalMark{Signal: AnthropicRefusalSignalRefusal})
	if GetAnthropicRefusalMark(nil) != nil {
		t.Fatal("nil context must return nil mark")
	}
	ClearAnthropicRefusalMark(nil)
}

func TestMarkAnthropicRefusalIgnoresEmptySignal(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(nil)
	MarkAnthropicRefusal(c, AnthropicRefusalMark{Signal: "  "})
	if GetAnthropicRefusalMark(c) != nil {
		t.Fatal("empty signal must not create a mark")
	}
}

func TestDetectAnthropicRefusalSSEData(t *testing.T) {
	cases := []struct {
		name string
		data string
		want bool
	}{
		{"refusal delta", `{"type":"message_delta","delta":{"stop_reason":"refusal"},"usage":{"output_tokens":1}}`, true},
		{"end_turn delta", `{"type":"message_delta","delta":{"stop_reason":"end_turn"}}`, false},
		{"message_start", `{"type":"message_start","message":{"usage":{"input_tokens":3}}}`, false},
		{"done marker", `[DONE]`, false},
		{"empty", ``, false},
		{"garbage", `not json`, false},
		// stop_reason 只在 message_delta 上有意义；别的事件里出现同名字段不算数。
		{"wrong event type", `{"type":"content_block_delta","delta":{"stop_reason":"refusal"}}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := DetectAnthropicRefusalSSEData(tc.data); got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}
