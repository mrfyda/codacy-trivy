package main

import (
	"encoding/json"
	"fmt"

	"github.com/aquasecurity/trivy/pkg/fanal/secret"
)

func main() {

	rules := secret.NewScanner(nil).Rules
	jsonResults, _ := json.Marshal(rules)
	fmt.Print(string(jsonResults))

}
