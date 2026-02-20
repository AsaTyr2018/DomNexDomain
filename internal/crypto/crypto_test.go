package crypto

import "testing"

func TestPasswordHashVerify(t *testing.T) {
	h, err := HashPassword("secret123", DefaultArgonConfig())
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword("secret123", h) {
		t.Fatal("verify failed")
	}
	if VerifyPassword("wrong", h) {
		t.Fatal("verify should fail")
	}
}
