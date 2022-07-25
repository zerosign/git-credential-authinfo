package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

var (
	files []string = []string{
		".authinfo.gpg",
		".authinfo",
		".netrc.gpg",
		".netrc",
	}
)

type Credential struct {
	Host        string
	Username    string
	Application string
	Password    string
}

func readLine(line string) (Credential, error) {
	parts := strings.Split(line, " ")

	if len(parts) != 6 {
		return Credential{}, fmt.Errorf("line length mismatch, should be 6 words")
	}

	userApps := strings.Split(parts[3], "^")

	if len(userApps) != 2 {
		return Credential{}, fmt.Errorf("username & application doesn't exists")
	}

	return Credential{
		Host:        parts[1],
		Username:    userApps[0],
		Application: userApps[1],
		Password:    parts[5],
	}, nil
}

func main() {

	stdinScanner := bufio.NewScanner(bufio.NewReader(os.Stdin))

	for stdinScanner.Scan() {
		fmt.Println(stdinScanner.Text())
	}

	homeDir, err := os.UserHomeDir()

	if err != nil {
		log.Fatal(err)
	}

	localHomeFs := os.DirFS(homeDir)

	for _, file := range files {
		if _, err := fs.Stat(localHomeFs, file); err == nil {

			authInfoPath := filepath.Join(homeDir, file)

			if filepath.Ext(authInfoPath) == ".gpg" {

				fmt.Println("path: ", authInfoPath, filepath.Ext(authInfoPath))

				cmd := exec.Command("gpg", "--decrypt", authInfoPath)
				raw, err := cmd.Output()

				if err != nil {
					log.Fatal(err)
				}

				scanner := bufio.NewScanner(bytes.NewReader(raw))

				// machine [host] login [username]^[application] password [password]\n
				for scanner.Scan() {
					credential, err := readLine(scanner.Text())
					if err != nil {
						log.Fatal(err)
					}

					log.Println("credential: ", credential)
				}
			}
		}
	}

}
