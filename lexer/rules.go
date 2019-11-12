package lexer

/*
	The ERLang - (stands for E.V.E Rule Language) is a JSON-based, RegExp oriented instruction system,
		running in a deterministic finite state machine (https://en.wikipedia.org/wiki/Finite-state_machine).

	An EXPRESSION is a RegExp compliant (and UTF-8 MANDATORY) string,
		to be interpreted using the `regexp` module of the Go programming language.

	A FILE is a UTF-8 encoded file (or will be converted to that otherwise),
		representing some portion of the source code of a application to be analyzed.
		A thing that we have to pay attention is for example, the GBK enconding (Simplified Chinese)
		because we cannot lose the original structure of the file.

	An OPERATOR is a JSON key,
		that indicates which OPERATION have to be used with 1-N EXPRESSIONs,
		to change the state either to POSITIVE MATCH, or NEGATIVE MATCH

	A FINDING is the join of a LINE and a COLUMN that an EXPRESSION have found in the FILE

	############## States ##############
	POSITIVE MATCH -> When an EXPRESSION returns TRUE, needs to be evaluated to a FINDING
	NEGATIVE MATCH -> When an EXPRESSION returns FALSE, returns to SEARCH state
	SEARCH -> Default state where expects to receive another EXPRESSION to be evaluated
		only can move to POSITIVE MATCH, or NEGATIVE MATCH

	############## OPERATORs syntax ##############
	$and -> An array of EXPRESSIONs to be interpreted as: EXPRESSION #1 && EXPRESSION #2 &&...,
		and if, and only if ALL of the EXPRESSIONs return a POSITIVE MATCH state, we have a FINDING

	$or -> An array of EXPRESSIONs to be interpreted as: EXPRESSION #1 || EXPRESSION #2 ||...,
		and if any of the EXPRESSIONs evaluate positively, returns a FINDING

	$match -> Single EXPRESSION to found a pattern in text,
		that if evaluate to POSITIVE MATCH state, becomes a FINDING

	$notAnd -> An array of EXPRESSION to be evaluated as [OPERATOR] && !(EXPRESSION #1 && EXPRESSION #2 &&...)
		which evaluates to the POSITIVE MATCH state only if all EXPRESSIONs returns a POSITIVE MATCH

	$notOr -> An array of EXPRESSION to be evaluated as [OPERATOR] && !(EXPRESSION #1 && EXPRESSION #2 &&...)
		which evaluates to the POSITIVE MATCH state if any EXPRESSION returns a POSITIVE MATCH


	############## Preprocessing operators and/or external related to a FILE ##############
	$filter -> Used to filter the FILE extension (ignoring magic bytes for now)

	$libraries ->	Evaluated as [OPERATOR] && foreach LIBRARY -> Libraries contains LIBRARY,
		returning a POSITIVE MATCH only if all defined LIBRARY was found insinde the libraries list.

	$permissions -> Evaluated as [OPERATOR] && foreach PERMISSION -> Permissions contains PERMISSION,
		returning a POSITIVE MATCH only if all defined PERMISSION was found inside the permissions list.
*/

// Rule contains the data about how a SAST rule looks like
// who interprets this structure is analyzers/static.go file
type Rule struct {
	// Basic operators
	AndExpressions []string
	OrExpressions  []string
	ExactMatch     string
	Libraries      []string
	Permissions    []string
	FileFilter     string
	NotAnd         []string
	NotOr          []string
	NotMatch       string
	// Indicative about the operators to make the engine job easier
	IsAndMatch       bool
	IsOrMatch        bool
	HaveNotANDClause bool
	HaveNotORClause  bool
	IsNotMatch       bool
	IsBinaryFileRule bool
	// Informative description
	CWE              string
	Title            string
	Description      string
	Recomendation    string
	Severity         string
	OWASPReferenceID string
}

// LoadRules loads the Ruleset for the given
// techstack and the default (core.json) one
func LoadRules(techStack string) ([]Rule, error) {
	var requiredRules []Rule
	coreRules := getJSONRuleset("core")

	requiredRules = append(requiredRules, coreRules...)

	moreRules := getJSONRuleset(techStack)

	requiredRules = append(requiredRules, moreRules...)

	return requiredRules, nil
}
