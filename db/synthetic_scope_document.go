package db

import "github.com/Autumn-27/artex/security/strictjson"

// Scope syntax validation is not target authorization or schema validation.
const maxSyntheticScopeDepth = 128

func validSyntheticScopeDocument(document []byte) bool {
	return strictjson.ValidObject(document, 65536, maxSyntheticScopeDepth)
}
