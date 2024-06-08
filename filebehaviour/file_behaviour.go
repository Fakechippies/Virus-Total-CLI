package filebehaviour

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

func GetFileBehaviour(filePath string) {
	file, err := os.Open(filePath)
	if err != nil {
		fmt.Printf("Error opening file : %v\n", err)
		return
	}
	defer file.Close()

	url := "https://www.virustotal.com/api/v3/files"
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		fmt.Printf("Error creating request : %v\n", err)
		return
	}

	req.Header.Set("x-api-key", apiKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Printf("Error sending request : %v\n", err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response : %v\n", err)
		return
	}

	var result map[string]interface{}
	err = json.Unmarshal(body, &result)
	if err != nil {
		fmt.Printf("Error parsing response : %v\n", err)
		return
	}

	analysisID := result["data"].(map[string]interface{})["id"].(string)

	url = fmt.Sprintf("https://www.virustotal.com/api/v3/analyses/%s", analysisID)
	req, err = http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Printf("Error sending request : %v\n", err)
		return
	}

	req.Header.Set("x-api-key", apiKey)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		fmt.Printf("Error creating request : %v\n", err)
		return
	}
	resp.Body.Close()

	body, err = io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response : %v\n", err)
		return
	}

	err = json.Unmarshal(body, &result)
	if err != nil {
		fmt.Printf("Error parsing response : %v\n", err)
		return
	}

	fmt.Printf("File Behaviour : %v\n", result)
}
