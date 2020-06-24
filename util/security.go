package util

import "log"

func CheckSecurityScore(security, securityscore int) {
	if securityscore < security {
		log.Fatalf("Score Security %v lower then %v", securityscore, security)
	}
}
