package txtfilemaker

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
)

// report creation struct
type AnalysisData struct {
	Data struct {
		Attributes struct {
			Date    int64 `json:"date"`
			Results map[string]struct {
				Category      string  `json:"category"`
				EngineName    string  `json:"engine_name"`
				EngineUpdate  string  `json:"engine_update"`
				EngineVersion string  `json:"engine_version"`
				Method        string  `json:"method"`
				Result        *string `json:"result"`
			} `json:"results"`
			Stats struct {
				ConfirmedTimeout int `json:"confirmed-timeout"`
				Failure          int `json:"failure"`
				Harmless         int `json:"harmless"`
				Malicious        int `json:"malicious"`
				Suspicious       int `json:"suspicious"`
				Timeout          int `json:"timeout"`
				TypeUnsupported  int `json:"type-unsupported"`
				Undetected       int `json:"undetected"`
			} `json:"stats"`
			Status string `json:"status"`
		} `json:"attributes"`
		ID    string `json:"id"`
		Links struct {
			Item string `json:"item"`
			Self string `json:"self"`
		} `json:"links"`
		Type string `json:"type"`
	} `json:"data"`
	Meta struct {
		FileInfo struct {
			MD5    string `json:"md5"`
			SHA1   string `json:"sha1"`
			SHA256 string `json:"sha256"`
			Size   int    `json:"size"`
		} `json:"file_info"`
	} `json:"meta"`
}

func TxtfileMaker() {
	// opening json file
	loadCounter()
	counter++
	filename := fmt.Sprintf("Report-%d.json", counter)
	jsonFile, err := os.Open(filename)
	if err != nil {
		log.Fatalf("Failed to open JSON file: %s", err)
	}
	defer jsonFile.Close()

	// reading json file
	jsonData, err := io.ReadAll(jsonFile)
	if err != nil {
		log.Fatalf("Failed to read JSON file: %s", err)
	}

	//creating a txt file
	file, err := os.Create("malware1.txt")
	if err != nil {
		log.Fatalf("Failed to create file: %s", err)
	}
	defer file.Close()

	// putting json data into struct
	var analysisData AnalysisData
	err = json.Unmarshal(jsonData, &analysisData)
	if err != nil {
		log.Fatalf("Failed to unmarshal JSON data: %s", err)
	}

	//writing in the file
	_, err = file.WriteString("\t\t\tAnalysis Report of the sample\n\n\n")
	_, err = file.WriteString("ID: " + analysisData.Data.ID + "\n" + "Status: " + analysisData.Data.Attributes.Status + "\n")
	_, err = file.WriteString("Date: " + fmt.Sprintf("%d", analysisData.Data.Attributes.Date) + "\n\n")
	_, err = file.WriteString("Stats: \n" + fmt.Sprintf("  Confirmed Timeout: %d", analysisData.Data.Attributes.Stats.ConfirmedTimeout) + "\n")
	_, err = file.WriteString(fmt.Sprintf("  Failure: %d", analysisData.Data.Attributes.Stats.Failure) + "\n")
	_, err = file.WriteString(fmt.Sprintf("  Harmless: %d", analysisData.Data.Attributes.Stats.Harmless) + "\n")
	_, err = file.WriteString(fmt.Sprintf("  Malicious: %d", analysisData.Data.Attributes.Stats.Malicious) + "\n")
	_, err = file.WriteString(fmt.Sprintf("  Suspicious: %d", analysisData.Data.Attributes.Stats.Suspicious) + "\n")
	_, err = file.WriteString(fmt.Sprintf("  Timeout: %d", analysisData.Data.Attributes.Stats.Timeout) + "\n")
	_, err = file.WriteString(fmt.Sprintf("  Type Unsupported: %d", analysisData.Data.Attributes.Stats.TypeUnsupported) + "\n")
	_, err = file.WriteString(fmt.Sprintf("  Undetected: %d", analysisData.Data.Attributes.Stats.Undetected) + "\n\n")
	_, err = file.WriteString("File Info: \n" + fmt.Sprintf("  MD5: %s", analysisData.Meta.FileInfo.MD5) + "\n")
	_, err = file.WriteString(fmt.Sprintf("  SHA1: %s", analysisData.Meta.FileInfo.SHA1) + "\n")
	_, err = file.WriteString(fmt.Sprintf("  SHA256: %s", analysisData.Meta.FileInfo.SHA256) + "\n")
	_, err = file.WriteString(fmt.Sprintf("  Size: %d", analysisData.Meta.FileInfo.Size) + "\n\n")

	for key, result := range analysisData.Data.Attributes.Results {
		_, err = file.WriteString(fmt.Sprintf("Engine: %s", key) + "\n")
		_, err = file.WriteString(fmt.Sprintf("  Category: %s", result.Category) + "\n")
		_, err = file.WriteString(fmt.Sprintf("  Engine Name: %s", result.EngineName) + "\n")
		_, err = file.WriteString(fmt.Sprintf("  Engine Update: %s", result.EngineUpdate) + "\n")
		_, err = file.WriteString(fmt.Sprintf("  Engine Version: %s", result.EngineVersion) + "\n")
		_, err = file.WriteString(fmt.Sprintf("  Method: %s", result.Method) + "\n")
		_, err = file.WriteString(fmt.Sprintf("  Result: %v", result.Result) + "\n")
	}

	_, err = file.WriteString("\n")

	err1 := os.Remove("malware1.json")
	if err1 != nil {
		fmt.Println("Error Deleting file")
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
