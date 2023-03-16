package hasher

// hasherLibrary is a map of all available hashers.
var hasherLibrary = map[string]Hasher{}

func init() {
	// Register the default hashers.
	hasherLibrary["pbkdf2_sha256"] = PBKDF2PasswordHasher
	hasherLibrary["pbkdf2_sha1"] = PBKDF2SHA1PasswordHasher
}
