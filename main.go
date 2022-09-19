package main

import (
	"fmt"
	"os"

	"github.com/ono-re-engines/go-jwt-sample/app/jwttkn"
)

func main() {
	fmt.Println("Starting JWT sample application...")

	// JWT Tokenの作成
	c := jwttkn.NewClaims("test code")
	tokenString, err := jwttkn.NewRSASignedStringWithClaims(c)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	fmt.Printf("Token string is %s\n", tokenString)

	// JWT Tokenのパース
	token, err := jwttkn.ParseRSASigned(tokenString)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	if claims, err := jwttkn.GetClaims(token); err == nil {
		fmt.Printf("claims are %v\n", claims)
	} else {
		fmt.Println(err.Error())
	}

	fmt.Println("Ending the JWT sample application...")
}
