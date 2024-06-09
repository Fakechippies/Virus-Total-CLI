package main

import (
	"bufio"
	"fmt"
	"github.com/Fakechippies/Virus-Total-API/scanfile"
	"github.com/Fakechippies/Virus-Total-API/scanurl"
	"os"
)

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Println("\nVirusTotal CLI")
		fmt.Println("1. Scan a file for viruses")
		fmt.Println("2. Scan a URL for malicious activity")
		fmt.Println("3. Exit")
		fmt.Print("Enter your choice: ")

		scanner.Scan()
		choice := scanner.Text()

		switch choice {
		case "1":
			fmt.Print("Enter the file path: ")
			scanner.Scan()
			filePath := scanner.Text()
			scanfile.Scanfile(filePath)
		case "2":
			fmt.Print("Enter the URL: ")
			scanner.Scan()
			url := scanner.Text()
			scanurl.ScanURL(url)
		case "3":
			fmt.Println("Exiting...  ")
			return
		default:
			fmt.Println("Invalid choice, please try again.")
		}
	}
}
