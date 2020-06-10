package hasher

import "testing"

func TestNew(t *testing.T) {
	hasher, err := New(1000, 128, 256, HashSHA256)
	if err != nil {
		t.Errorf("didn't expect to get an error: %v", err)
		return
	}

	if hasher == nil {
		t.Errorf("didn't expect a nin-pointer for hasher")
		return
	}

	t.Run("Invalid Iteration Count", func(t *testing.T) {
		_, err := New(0, 128, 256, HashSHA256)
		if err != ErrInvalidIterationCount {
			t.Errorf("expected '%v' but got '%v'", ErrInvalidIterationCount, err)
		}
	})

	t.Run("Invalid Salt Size", func(t *testing.T) {
		// negative salt size
		_, err := New(1000, -1, 256, HashSHA256)
		if err != ErrInvalidSaltSize {
			t.Errorf("expected '%v' bot got '%v'", ErrInvalidSaltSize, err)
		}

		// not a multiple of 8
		_, err = New(1000, 14, 256, HashSHA256)
		if err != ErrInvalidSaltSize {
			t.Errorf("expected '%v' bot got '%v'", ErrInvalidSaltSize, err)
		}
	})

	t.Run("Invalid Key Size", func(t *testing.T) {
		// negative key size
		_, err := New(1000, 128, -1, HashSHA256)
		if err != ErrInvalidKeySize {
			t.Errorf("expected '%v' bot got '%v'", ErrInvalidKeySize, err)
		}

		// not a multiple of 8
		_, err = New(1000, 128, 14, HashSHA256)
		if err != ErrInvalidKeySize {
			t.Errorf("expected '%v' bot got '%v'", ErrInvalidKeySize, err)
		}
	})
}

func TestHash(t *testing.T) {
	pwd := "MyTestPassword"
	hash := Hash([]byte(pwd))

	t.Run("Format", func(t *testing.T) {
		if hash[0] != formatMarker {
			t.Errorf("expected '%v' at the start of the hash but got '%b'", formatMarker, hash[0])
		}
	})

	t.Run("Scan", func(t *testing.T) {
		_, iterCnt, saltSize := scanHeader(hash)
		if iterCnt != DefaultIterationCount {
			t.Errorf("expected an iteration count of %d, but got %d", DefaultIterationCount, iterCnt)
		}

		if saltSize != DefaultSaltSize/8 {
			t.Errorf("expected a salt size of %d, but got %d", DefaultSaltSize/8, saltSize)
		}
	})
}

func TestAlg(t *testing.T) {
	keys := map[string]int{
		"SHA256": HashSHA256,
		"SHA512": HashSHA512,
	}

	for name, value := range keys {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("unexpected panic: %v", r)
				}
			}()

			f := alg(value)
			if f == nil {
				t.Errorf("expected func() hash.Hash, but got nil")
			}
		})
	}

	t.Run("Unsupported", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("expected a panic")
			}
		}()

		// 237 is not aa recognised key
		_ = alg(237)
	})
}

func TestVerify(t *testing.T) {
	pwd := []byte("MyTestPassword")
	hash := Hash(pwd)

	ok := Verify(pwd, hash)
	if !ok {
		t.Errorf("expected hash to be valid")
	}

	t.Run("Empty Hash", func(t *testing.T) {
		ok := Verify(pwd, []byte{})
		if ok {
			t.Errorf("expected hash to be invalid")
		}
	})

	t.Run("Correct Format", func(t *testing.T) {
		hash[0] = 0x23 // invalid format marker
		ok := Verify(pwd, hash)
		if ok {
			t.Errorf("expected hash to be invalid")
		}
	})

	t.Run("Invalid Salt Size", func(t *testing.T) {
		hasher, _ := New(DefaultIterationCount, 32, DefaultKeySize, DefaultHashKey)
		hash := hasher.Hash(pwd)
		ok := Verify(pwd, hash)
		if ok {
			t.Errorf("expected hash to be invalid")
		}
	})

	t.Run("Invalid Key Size", func(t *testing.T) {
		hasher, _ := New(DefaultIterationCount, DefaultSaltSize, 128, DefaultHashKey)
		hash := hasher.Hash(pwd)
		ok := Verify(pwd, hash)
		if ok {
			t.Errorf("expected hash to be invalid")
		}
	})

	t.Run("Invalid Hash", func(t *testing.T) {
		ok := Verify(pwd, hash[:12])
		if ok {
			t.Errorf("expected hash to be invalid")
		}
	})
}
