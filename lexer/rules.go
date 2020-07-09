package lexer

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"reflect"
	"strings"
)

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
		returning a POSITIVE MATCH only if all defined PERMISSION was found insinde the permissions list.
*/

// Rule contains the data about how a SAST rule looks like
// who interprets this structure is analyzers/static.go file
type Rule struct {
	// Basic operators
	AndExpressions []string `json:"$and"`
	OrExpressions  []string `json:"$or"`
	ExactMatch     string   `json:"$match"`
	Libraries      []string `json:"$libraries"`
	Permissions    []string `json:"$permissions"`
	FileFilter     string   `json:"$filter"`
	NotAnd         []string `json:"$notAnd"`
	NotOr          []string `json:"$notOr"`
	NotMatch       string   `json:"$not"`
	// Indicative about the operators to make the engine job easier
	IsAndMatch       bool `json:"andMatch"`
	IsOrMatch        bool `json:"orMatch"`
	HaveNotANDClause bool `json:"notAndMatch"`
	HaveNotORClause  bool `json:"notOrMatch"`
	IsNotMatch       bool `json:"notMatch"`
	IsBinaryFileRule bool `json:"binaryMatch"`
	// Informative description
	CWE               string  `json:"cwe"`
	AverageCVSS       float64 `json:"cvss"`
	Title             string  `json:"title"`
	Severity          string  `json:"level"`
	Description       string  `json:"description"`
	Description_pt_br string  `json:"description_PT-BR"`
	Description_en    string  `json:"description_EN"`
	Description_es    string  `json:"description_ES"`

	Recomendation       string `json:"recomendation"`
	Recomendation_pt_br string `json:"recomendation_PT-BR"`
	Recomendation_en    string `json:"recomendation_EN"`
	Recomendation_es    string `json:"recomendation_ES"`
}

func getJSONRuleset(filename string, lang string) ([]Rule, error) {
	var rules []Rule
	switch filename {
	case "lexer/data/android.json":
		rules = AndroidRules(lang)
	case "lexer/data/core.json":
		rules = CoreRules(lang)
	case "lexer/data/csharp.json":
		rules = CsharpRules(lang)
	case "lexer/data/javascript.json":
		rules = JavascriptRules(lang)
	case "lexer/data/ios.json":
		rules = IosRules(lang)
	}

	for i, v := range rules {
		r := reflect.ValueOf(v)
		desc := reflect.Indirect(r).FieldByName("Description_" + strings.ToLower(lang))
		rec := reflect.Indirect(r).FieldByName("Recomendation_" + strings.ToLower(lang))
		rules[i].Description = desc.String()
		rules[i].Recomendation = rec.String()
	}
	log.Println("Rules", len(rules))
	return rules, nil
}

func getJSONRuleset_HC(filename string, lang string) ([]Rule, error) {

	xi := AndroidRules(lang)

	physicalPathToFile := resolveToRuleDataFolder(filename)

	ruleset, err := ioutil.ReadFile(physicalPathToFile)

	if err != nil {
		return nil, err
	}

	var rules []Rule

	err = json.Unmarshal(ruleset, &rules)

	if err != nil {
		return nil, err
	}

	//  setting the language of the rule.
	for i, v := range rules {
		r := reflect.ValueOf(v)
		desc := reflect.Indirect(r).FieldByName("Description_" + lang)
		rec := reflect.Indirect(r).FieldByName("Recomendation_" + lang)
		rules[i].Description = desc.String()
		rules[i].Recomendation = rec.String()
	}

	log.Println("Rule class", len(xi))
	log.Println("Rule files", len(rules))
	//for i, v := range rules {
	//	log.Println(i, v)
	//}

	return rules, nil
}

// LoadRules loads the Ruleset for the given
// techstack and the default (core.json) one
func LoadRules(techStack string, lang string) ([]Rule, error) {
	var requiredRules []Rule
	log.Println("loading core rules")
	coreRules, err := getJSONRuleset("lexer/data/core.json", lang)

	if err != nil {
		return nil, err
	}

	requiredRules = append(requiredRules, coreRules...)

	switch techStack {
	case "android":
		log.Println("loading android rules")
		androidRules, err := getJSONRuleset("lexer/data/android.json", lang)

		if err != nil {
			return nil, err
		}

		requiredRules = append(requiredRules, androidRules...)
	case "ios":
		log.Println("loading IOS rules")
		iosRules, err := getJSONRuleset("lexer/data/ios.json", lang)

		if err != nil {
			return nil, err
		}

		requiredRules = append(requiredRules, iosRules...)
	case "csharp":
		log.Println("loading csharp rules")
		csharpRules, err := getJSONRuleset("lexer/data/csharp.json", lang)

		if err != nil {
			return nil, err
		}

		requiredRules = append(requiredRules, csharpRules...)
	case "iosBinary":
		iosBinaryRules, err := getJSONRuleset("lexer/data/ios_binary.json", lang)

		if err != nil {
			return nil, err
		}

		requiredRules = append(requiredRules, iosBinaryRules...)
	case "javascript":
		javaScriptRules, err := getJSONRuleset("lexer/data/javascript.json", lang)

		if err != nil {
			return nil, err
		}

		requiredRules = append(requiredRules, javaScriptRules...)
	case "java":
		javaRules, err := getJSONRuleset("lexer/data/java.json", lang)

		if err != nil {
			return nil, err
		}

		requiredRules = append(requiredRules, javaRules...)
	case "core":
		return requiredRules, nil
	default:
		return nil, errors.New("Invalid tech stack")
	}

	return requiredRules, nil
}
