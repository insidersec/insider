package lexer

var rulesets map[string][]Rule = map[string][]Rule{}

func init() {
	rulesets["ios"] = ios
	rulesets["core"] = core
	rulesets["csharp"] = csharp
	rulesets["android"] = android
	rulesets["javascript"] = javascript
}

func getJSONRuleset(filename string) []Rule {
	return rulesets[filename]
}
