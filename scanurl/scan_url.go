package scanurl

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Fakechippies/Virus-Total-API/txtfilemaker"
	"github.com/joho/godotenv"
)

var apiKey string

func init() {
	err := godotenv.Load()
	if err != nil {
		fmt.Printf("Error loading .env file ")
		os.Exit(1)
	}
	apiKey = os.Getenv("VIRUSTOTAL_API_KEY")
}

func ScanURL(urlToScan string) {
	url := "https://www.virustotal.com/api/v3/urls"
	req, err := http.NewRequest("POST", url, strings.NewReader(fmt.Sprintf("url=%s", urlToScan)))
	if err != nil {
		fmt.Printf("Error creating request : %v\n", err)
		return
	}

	req.Header.Set("x-apikey", apiKey)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
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

	var submissionResponse map[string]interface{}
	err = json.Unmarshal(body, &submissionResponse)
	if err != nil {
		fmt.Printf("Error parsing response : %v\n", err)
		return
	}

	data := submissionResponse["data"].(map[string]interface{})
	id := data["id"].(string)

	time.Sleep(15 * time.Second)

	url = fmt.Sprintf("https://www.virustotal.com/api/v3/analyses/%s", id)
	req, err = http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Printf("Error creating request : %v\n", err)
		return
	}

	req.Header.Set("x-apikey", apiKey)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		fmt.Printf("Error sending request : %v\n", err)
		return
	}
	defer resp.Body.Close()

	body, err = io.ReadAll(resp.Body)
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

	prettyJSON, err := json.MarshalIndent(result, "", "    ")
	if err != nil {
		fmt.Printf("Failed to generate pretty JSON: %v\n", err)
		return
	}

	fmt.Printf("Scan Result:\n%s\n", string(prettyJSON))

	// Writing to file
	loadCounter()

	counter++
	filename := fmt.Sprintf("Report-%d.json", counter)
	information := string(prettyJSON)
	err = writeToFile(filename, information)
	if err != nil {
		fmt.Printf("Error writing to file: %v\n", err)
		return
	}

	fmt.Printf("Scan results saved to %s\n", filename)

	saveCounter()
	txtfilemaker.TxtfileMaker()
}

// Counter defination
var counter int

func loadCounter() {
	file, err := os.Open("counter.txt")
	if err != nil {
		// Default counter value if the file doesn't exist
		counter = 0
		return
	}
	defer file.Close()

	data := make([]byte, 100)
	n, err := file.Read(data)
	if err != nil {
		counter = 0
		return
	}
	val, err := strconv.Atoi(string(data[:n]))
	if err != nil {
		counter = 0
		return
	}

	counter = val
}

func writeToFile(filename string, data string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.WriteString(data)
	if err != nil {
		return err
	}

	return nil
}

func saveCounter() {
	file, err := os.Create("counter.txt")
	if err != nil {
		fmt.Printf("Error saving counter: %v\n", err)
		return
	}
	defer file.Close()

	_, err = file.WriteString(strconv.Itoa(counter))
	if err != nil {
		fmt.Printf("Error saving counter: %v\n", err)
	}
}
