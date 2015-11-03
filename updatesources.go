package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/x30n/ct-toys/models"
)

type Operator struct {
	Name string `json:"name"`
	Id   int    `json:"id"`
}

type JSONLogData struct {
	Operators []*Operator         `json:"operators"`
	Logs      []*models.LogSource `json:"logs"`
}

type Env struct {
	db models.Datastore
}

func main() {
	// TODO: Connection string needs to be put in configs
	db, err := models.NewDB("postgres://localhost/ctmonitor?sslmode=disable")
	if err != nil {
		log.Panic(err)
	}

	env := &Env{db}

	env.fetchAllLogSources()

}

func (env *Env) fetchAllLogSources() {

	// TODO: URL needs to be put in configs
	url := "https://www.certificate-transparency.org/known-logs/all_logs_list.json"

	resp, err := http.Get(url)

	defer resp.Body.Close()

	if err != nil {
		panic(err)
	}

	jsonDataFromHttp, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		panic(err)
	}

	var jsonData JSONLogData

	err = json.Unmarshal([]byte(jsonDataFromHttp), &jsonData)

	if err != nil {
		panic(err)
	}
	for _, log := range jsonData.Logs {
		// This mess is all just to ensure that the lookup of operator Name
		// works. Can't assume that the order of Operators in JSON is consistent
		// with their intended indexes.
		found := false
		operatorIdx := 0
		if jsonData.Operators[log.Operator[0]].Id == log.Operator[0] {
			operatorIdx = log.Operator[0]
			found = true
		} else {
			for i, op := range jsonData.Operators {
				if op.Id == log.Operator[0] {
					operatorIdx = i
					found = true
				}
			}
			if !found {
				// Definitely need better error handling that this
				panic("Operator index not found!\n")
			}
		}
		log.OperatedBy = jsonData.Operators[operatorIdx].Name
		// End of operator lookup mess
		_, err := env.db.LogSourceCreateOrUpdate(*log)
		if err != nil {
			panic(err)
		}
		// fmt.Printf("%s\t%s\t%s\t%d\t%s\n", log.Description, log.PubKey, log.URL, log.MaxMergeDelay, jsonData.Operators[operatorIdx].Name)
	}

	// fmmt.Println(jsonData.Operators[0].Name)
}
