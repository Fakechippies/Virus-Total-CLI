package main

import (
	"bufio"
	"fmt"
	"github.com/Fakechippies/Virus-Total-API/attacktactics"
	"github.com/Fakechippies/Virus-Total-API/domainreport"
	"github.com/Fakechippies/Virus-Total-API/filebehaviour"
	"github.com/Fakechippies/Virus-Total-API/ipreport"
	"github.com/Fakechippies/Virus-Total-API/scanfile"
	"github.com/Fakechippies/Virus-Total-API/scanurl"
	"github.com/Fakechippies/Virus-Total-API/searchgraphs"
	"github.com/Fakechippies/Virus-Total-API/threatcomparison"
	"os"
)

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Println("\nVirusTotal CLI")
		fmt.Println("1. Scan a file for viruses")
		fmt.Println("2. Scan a URL for malicious activity")
		fmt.Println("3. Get IP address report")
		fmt.Println("4. Get domain report")
		fmt.Println("5. Get file behaviour")
		fmt.Println("6. Get attack tactics")
		fmt.Println("7. Popular threat comparison")
		fmt.Println("8. Search graphs")
		fmt.Println("9. Exit")
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
			fmt.Print("Enter the IP address: ")
			scanner.Scan()
			ip := scanner.Text()
			ipreport.GetIPReport(ip)
		case "4":
			fmt.Print("Enter the Domain: ")
			scanner.Scan()
			domain := scanner.Text()
			domainreport.GetDomainReport(domain)
		case "5":
			fmt.Print("Enter the file path: ")
			scanner.Scan()
			filePath := scanner.Text()
			filebehaviour.GetFileBehaviour(filePath)
		case "6":
			attacktactics.GetAttackTactics()
		case "7":
			fmt.Print("Enter the hash: ")
			scanner.Scan()
			hash := scanner.Text()
			threatcomparison.PopularThreatComparison(hash)
		case "8":
			fmt.Print("Enter the hash(file, URL, domain, or IP): ")
			scanner.Scan()
			hash := scanner.Text()
			searchgraphs.GetSearchGraph(hash)
		case "9":
			fmt.Println("Exiting...  ")
			return
		default:
			fmt.Println("Invalid choice, please try again.")
		}
	}
}
