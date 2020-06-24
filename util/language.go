package util

func GetSeverity(lang string, Severity int) string {
	es := []string{"Info", "Bajo", "Bedio", "Alta"}
	en := []string{"Info", "Low", "Medium", "High"}
	pr_br := []string{"Info", "Baixa", "Média", "Alta"}
	if lang == "es" {
		return es[Severity]
	}
	if lang == "en" {
		return en[Severity]
	}
	return pr_br[Severity]
}
