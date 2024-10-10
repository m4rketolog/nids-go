package main

import (
	"bufio"
	"os"
	"strings"
)

func loadIPListFromFile(fileName string, targetMap map[string]bool) error {
	file, err := os.Open(fileName)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ip := strings.TrimSpace(scanner.Text())
		if ip != "" {
			targetMap[ip] = true
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}
