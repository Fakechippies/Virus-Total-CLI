package scanfile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"strconv"
	"time"

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

func Scanfile(filePath string) {
	file, err := os.Open(filePath)
	if err != nil {
		fmt.Printf("Error opening file: %v\n", err)
		return
	}
	defer file.Close()

	var requestBody bytes.Buffer
	writer := multipart.NewWriter(&requestBody)
	part, err := writer.CreateFormFile("file", file.Name())
	if err != nil {
		fmt.Printf("Error creating form file: %v\n", err)
		return
	}

	_, err = io.Copy(part, file)
	if err != nil {
		fmt.Printf("Error copying file: %v\n", err)
		return
	}
	writer.Close()

	url := "https://www.virustotal.com/api/v3/files"
	req, err := http.NewRequest("POST", url, &requestBody)
	if err != nil {
		fmt.Printf("Error creating request: %v\n", err)
		return
	}

	req.Header.Set("x-apikey", apiKey)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Printf("Error sending request: %v\n", err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response: %v\n", err)
		return
	}

	var submissionResponse map[string]interface{}
	err = json.Unmarshal(body, &submissionResponse)
	if err != nil {
		fmt.Printf("Error parsing response: %v\n", err)
		return
	}

	data := submissionResponse["data"].(map[string]interface{})
	id := data["id"].(string)

	for {
		url = fmt.Sprintf("https://www.virustotal.com/api/v3/analyses/%s", id)
		req, err = http.NewRequest("GET", url, nil)
		if err != nil {
			fmt.Printf("Error creating request: %v\n", err)
			return
		}

		req.Header.Set("x-apikey", apiKey)
		resp, err = http.DefaultClient.Do(req)
		if err != nil {
			fmt.Printf("Error sending request: %v\n", err)
			return
		}
		defer resp.Body.Close()

		body, err = io.ReadAll(resp.Body)
		if err != nil {
			fmt.Printf("Error reading response: %v\n", err)
			return
		}

		var result map[string]interface{}
		err = json.Unmarshal(body, &result)
		if err != nil {
			fmt.Printf("Error parsing response: %v\n", err)
			return
		}

		status := result["data"].(map[string]interface{})["attributes"].(map[string]interface{})["status"].(string)
		if status == "completed" {
			prettyJSON, err := json.MarshalIndent(result, "", "    ")
			if err != nil {
				fmt.Printf("Failed to generate pretty JSON: %v\n", err)
				return
			}
			fmt.Printf("Scan Result:\n%s\n", string(prettyJSON))

			// Writing to file
			loadCounter()

			counter++
			filename := fmt.Sprintf("malware%d.json", counter)
			information := string(prettyJSON)
			err = writeToFile(filename, information)
			if err != nil {
				fmt.Printf("Error writing to file: %v\n", err)
				return
			}

			fmt.Printf("Scan results saved to %s\n", filename)

			saveCounter()
			break
		}

		fmt.Println("Analysis status:", status, "- waiting for completion...")
		time.Sleep(15 * time.Second)
	}
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
