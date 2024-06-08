package domainreport

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/joho/godotenv"
)

var apiKey string

func init() {
	err := godotenv.Load()
	if err != nil {
		fmt.Println("Error loading .env file")
		os.Exit(1)
	}
	apiKey = os.Getenv("VIRUSTOTAL_API_KEY")
}

func GetDomainReport(domain string) {
	url := fmt.Sprintf("https://www.virustotal.com/api/v3/domains/%s", domain)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Printf("Error creating request : %v\n", err)
		return
	}

	req.Header.Set("x-apikey", apiKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Printf("Error sending request : %v\n", err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading reponse : %v\n", err)
		return
	}

	var result map[string]interface{}
	err = json.Unmarshal(body, &result)
	if err != nil {
		fmt.Printf("Error parsing response : %v\n", err)
		return
	}

	fmt.Printf("Domain Report : %v\n", result)
}
