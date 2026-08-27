package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/olekukonko/tablewriter"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/disk"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	sliceutil "github.com/projectdiscovery/utils/slice"
	stringsutil "github.com/projectdiscovery/utils/strings"
	"gopkg.in/yaml.v2"
)

type Pair struct {
	Key   string `json:"name"`
	Value int    `json:"count"`
}

type PairList []Pair

func (p PairList) Len() int           { return len(p) }
func (p PairList) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }
func (p PairList) Less(i, j int) bool { return p[i].Value > p[j].Value }

func newPairListFromMap(data map[string]int, n int) PairList {
	pairs := make(PairList, len(data))
	i := 0

	for k, v := range data {
		pairs[i] = Pair{k, v}
		i++
	}
	sort.Sort(pairs)

	final := make([]Pair, 0, len(pairs))
	for i, data := range pairs {
		if n != 0 && i == n {
			break
		}
		final = append(final, data)
	}
	return final
}

var (
	count = flag.Int("top", 0, "Output top N number of tags")

	tagsFilter        = flag.Bool("tags", false, "Show Tags Data")
	authorFilter      = flag.Bool("authors", false, "Show Author Data")
	directoryFilter   = flag.Bool("directory", false, "Show Directory Data")
	severityFilter    = flag.Bool("severity", false, "Show Severity Data")
	typesFilter       = flag.Bool("types", false, "Show Types Data")
	verbose           = flag.Bool("v", false, "Use verbose mode")
	listCvesInReverse = flag.Bool("lcr", false, "List CVEs in reverse order")
	includeFields     = flag.String("fields", "", "Include fields in output. comma separated: authors,severity")
	ta                = flag.String("ta", "", "Template Addition file")
	outputFile        = flag.String("output", "", "File to write template addition author output to")
	jsonOutput        = flag.Bool("json", false, "Show output in json format")
	templateDirectory = flag.String("path", "", "Template Directory")
)

type Output struct {
	Tags      PairList `json:"tags,omitempty"`
	Authors   PairList `json:"authors,omitempty"`
	Directory PairList `json:"directory,omitempty"`
	Severity  PairList `json:"severity,omitempty"`
	Types     PairList `json:"types,omitempty"`
}

func (o *Output) getMaxItemCount() int {
	max := len(o.Tags)
	if newMax := len(o.Authors); newMax > max {
		max = newMax
	}
	if newMax := len(o.Directory); newMax > max {
		max = newMax
	}
	if newMax := len(o.Severity); newMax > max {
		max = newMax
	}
	if newMax := len(o.Types); newMax > max {
		max = newMax
	}
	return max
}

type NonCveItem struct {
	Id       string `json:"id"`
	Name     string `json:"name"`
	Author   string `json:"author"`
	Severity string `json:"severity"`
}

type NonCveList []NonCveItem

type CveItem struct {
	CveID    string `json:"cve_id"`
	Name     string `json:"name"`
	Author   string `json:"author"`
	Severity string `json:"severity"`
}

type CveList []CveItem

func (c CveList) Len() int      { return len(c) }
func (c CveList) Swap(i, j int) { c[i], c[j] = c[j], c[i] }
func (c CveList) Less(i, j int) bool {
	first := strings.Split(c[i].CveID, "-")
	second := strings.Split(c[j].CveID, "-")
	if len(first) < 1 || len(second) < 1 && len(first) != len(second) {
		return c[i].CveID > c[j].CveID
	}
	var err1, err2, err3, err4 error
	var firstYearPart, firstNumPart, secondYearPart, secondNumPart int
	firstYearPart, err1 = strconv.Atoi(first[1])
	firstNumPart, err2 = strconv.Atoi(first[2])
	secondYearPart, err3 = strconv.Atoi(second[1])
	secondNumPart, err4 = strconv.Atoi(second[2])
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
		return c[i].CveID > c[j].CveID
	}
	if firstYearPart > secondYearPart {
		return true
	} else if firstYearPart == secondYearPart {
		if firstNumPart > secondNumPart {
			return true
		}
	}
	return false
}

func main() {
	flag.Parse()

	if *templateDirectory == "" {
		homedir, err := os.UserHomeDir()
		if err != nil {
			log.Fatalf("%s\n", err)
		}
		*templateDirectory = filepath.Join(homedir, "nuclei-templates")
	}
	if *ta != "" {
		if err := printTemplateAdditions(*ta); err != nil {
			log.Fatalf("Could not print additions: %s\n", err)
		}
		return
	}
	printTemplateStats()
}

func printTemplateStats() {
	catalogClient := disk.NewCatalog(*templateDirectory)
	includedTemplates, err := catalogClient.GetTemplatePath(*templateDirectory)
	if err != nil {
		log.Fatal(err)
	}

	tagMap := make(map[string]int)
	authorMap := make(map[string]int)
	severityMap := make(map[string]int)
	directoryMap := make(map[string]int)
	typesMap := make(map[string]int)
	var cveList CveList
	var nonCveList NonCveList
	for _, template := range includedTemplates {
		templateRelativePath := stringsutil.TrimPrefixAny(template, *templateDirectory, "/", "\\")

		var firstItem string
		if !stringsutil.ContainsAny(templateRelativePath, "/", "\\") {
			firstItem = templateRelativePath
		} else {
			firstItem = templateRelativePath[:strings.IndexAny(templateRelativePath, "/\\")]
		}

		directoryMap[firstItem]++

		if !stringsutil.EqualFoldAny(filepath.Ext(template), ".yaml") {
			if *verbose {
				fmt.Printf("[ignored] %s\n", template)
			}
			continue
		}

		f, err := os.Open(template)
		if err != nil {
			log.Printf("Could not read %s: %s\n", template, err)
			continue
		}
		data := make(map[string]interface{})
		if err := yaml.NewDecoder(f).Decode(&data); err != nil {
			f.Close()
			log.Printf("Could not parse %s: %s\n", template, err)
			continue
		}
		f.Close()
		id, ok := data["id"]
		if !ok {
			continue
		}
		info := data["info"]
		if info == nil {
			continue
		}
		infoMap := info.(map[interface{}]interface{})

		if *listCvesInReverse {
			name := infoMap["name"]
			author := infoMap["author"]
			severity := infoMap["severity"]
			if strings.HasPrefix(fmt.Sprintf("%v", id), "CVE-") {
				cveList = append(cveList, CveItem{CveID: fmt.Sprintf("%v", id), Name: fmt.Sprintf("%v", name), Author: fmt.Sprintf("%v", author), Severity: fmt.Sprintf("%v", severity)})
			} else {
				nonCveList = append(nonCveList, NonCveItem{Id: fmt.Sprintf("%v", id), Name: fmt.Sprintf("%v", name), Author: fmt.Sprintf("%v", author), Severity: fmt.Sprintf("%v", severity)})
			}
			continue
		}

		tags := infoMap["tags"]
		if tags == nil {
			if *verbose {
				log.Printf("[lint] No tags found for template %s\n", template)
			}
		}
		description := infoMap["description"]
		if description == nil {
			if *verbose {
				log.Printf("[lint] No description found for template %s\n", template)
			}
		}
		reference := infoMap["reference"]
		if reference == nil {
			if *verbose {
				log.Printf("[lint] No reference found for template %s\n", template)
			}
		}
		tagsString := types.ToString(tags)

		individualTags := strings.Split(tagsString, ",")
		for _, tag := range individualTags {
			count, ok := tagMap[tag]
			if !ok {
				tagMap[tag] = 1
			} else {
				tagMap[tag] = count + 1
			}
		}

		author, ok := infoMap["author"]
		if !ok {
			log.Printf("[lint] no author found for template %s\n", template)
		}
		authorStr := types.ToString(author)

		severity, ok := infoMap["severity"]
		if ok {
			severityStr := strings.ToLower(types.ToString(severity))

			count, ok := severityMap[severityStr]
			if !ok {
				severityMap[severityStr] = 1
			} else {
				severityMap[severityStr] = count + 1
			}
		}

		for _, author := range explodeCommaSeparatedField(authorStr) {
			count, ok := authorMap[author]
			if !ok {
				authorMap[author] = 1
			} else {
				authorMap[author] = count + 1
			}
		}

		if _, ok := data["requests"]; ok {
			if count, ok := typesMap["http"]; !ok {
				typesMap["http"] = 1
			} else {
				typesMap["http"] = count + 1
			}
		}
		if _, ok := data["dns"]; ok {
			if count, ok := typesMap["dns"]; !ok {
				typesMap["dns"] = 1
			} else {
				typesMap["dns"] = count + 1
			}
		}
		if _, ok := data["network"]; ok {
			if count, ok := typesMap["network"]; !ok {
				typesMap["network"] = 1
			} else {
				typesMap["network"] = count + 1
			}
		}
		if _, ok := data["file"]; ok {
			if count, ok := typesMap["file"]; !ok {
				typesMap["file"] = 1
			} else {
				typesMap["file"] = count + 1
			}
		}
	}

	var resultWriter io.Writer
	if *outputFile != "" {
		output, err := os.Create(*outputFile)
		if err != nil {
			log.Fatalf("Could not create output file: %s\n", err)
		}
		resultWriter = output
	} else {
		resultWriter = os.Stdout
	}

	if len(cveList) > 0 || len(nonCveList) > 0 {
		sort.Sort(cveList)
		hasTopFilter := *count > 0
		if hasTopFilter && len(cveList) > *count {
			cveList = cveList[:*count]
		}
		fields := strings.Split(*includeFields, ",")
		fields = sliceutil.Dedupe(fields)
		for _, cve := range cveList {
			_, _ = resultWriter.Write([]byte(formatCveItem(cve, fields)))
		}
		*count = *count - len(cveList)
		if hasTopFilter && *count >= 0 {
			nonCveList = nonCveList[:*count]
		}
		for _, nc := range nonCveList {
			_, _ = resultWriter.Write([]byte(formatNonCveItem(nc, fields)))
		}
		os.Exit(0)
	}

	output := &Output{}
	if *tagsFilter || *authorFilter || *directoryFilter || *typesFilter || *severityFilter {
		// we have a filter. only run the asked one.
		if *tagsFilter {
			output.Tags = newPairListFromMap(tagMap, *count)
		}
		if *authorFilter {
			output.Authors = newPairListFromMap(authorMap, *count)
		}
		if *directoryFilter {
			output.Directory = newPairListFromMap(directoryMap, *count)
		}
		if *typesFilter {
			output.Types = newPairListFromMap(typesMap, *count)
		}
		if *severityFilter {
			output.Severity = newPairListFromMap(severityMap, *count)
		}
	} else {
		output.Tags = newPairListFromMap(tagMap, *count)
		output.Authors = newPairListFromMap(authorMap, *count)
		output.Directory = newPairListFromMap(directoryMap, *count)
		output.Types = newPairListFromMap(typesMap, *count)
		output.Severity = newPairListFromMap(severityMap, *count)
	}

	if *jsonOutput {
		if err := json.NewEncoder(resultWriter).Encode(output); err != nil {
			log.Fatalf("Could not encode json: %s\n", err)
		}
	} else {
		renderMarkdown(output, resultWriter)
	}
}

func renderMarkdown(output *Output, writer io.Writer) {
	maxItems := output.getMaxItemCount()

	data := make([][]string, maxItems)
	for i := range data {
		data[i] = make([]string, 10)
	}
	for i, tag := range output.Tags {
		data[i][0] = tag.Key
		data[i][1] = strconv.Itoa(tag.Value)
	}
	for i, tag := range output.Authors {
		data[i][2] = tag.Key
		data[i][3] = strconv.Itoa(tag.Value)
	}
	for i, tag := range output.Directory {
		data[i][4] = tag.Key
		data[i][5] = strconv.Itoa(tag.Value)
	}
	for i, tag := range output.Severity {
		data[i][6] = tag.Key
		data[i][7] = strconv.Itoa(tag.Value)
	}
	for i, tag := range output.Types {
		data[i][8] = tag.Key
		data[i][9] = strconv.Itoa(tag.Value)
	}
	table := tablewriter.NewWriter(writer)
	table.SetHeader([]string{"Tag", "Count", "Author", "Count", "Directory", "Count", "Severity", "Count", "Type", "Count"})
	table.SetBorders(tablewriter.Border{Left: true, Top: false, Right: true, Bottom: false})
	table.SetCenterSeparator("|")
	table.AppendBulk(data) // Add Bulk Data
	table.Render()
}

func printTemplateAdditions(additionFile string) error {
	f, err := os.Open(additionFile)
	if err != nil {
		return errors.Wrap(err, "could not open addition file")
	}
	defer f.Close()

	output, err := os.Create(*outputFile)
	if err != nil {
		return errors.Wrap(err, "could not open output file file")
	}
	defer output.Close()

	var cveList CveList
	var nonCveList NonCveList
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		text := scanner.Text()

		templatePath := filepath.Join(*templateDirectory, text)

		if !stringsutil.EqualFoldAny(filepath.Ext(templatePath), ".yaml") {
			log.Printf("ignoring %s\n", templatePath)
			continue
		}

		template, err := os.Open(templatePath)
		if err != nil {
			log.Printf("Could not open %s: %s\n", text, err)
			continue
		}

		data := make(map[string]interface{})
		if err := yaml.NewDecoder(template).Decode(data); err != nil {
			template.Close()
			log.Printf("Could not decode %s: %s\n", text, err)
			continue
		}
		template.Close()

		id, ok := data["id"]
		if !ok {
			continue
		}
		info, ok := data["info"]
		if !ok {
			log.Printf("no info found for template %s\n", text)
			continue
		}
		infoMap := info.(map[interface{}]interface{})
		author, ok := infoMap["author"]
		if !ok {
			log.Printf("no author found for template %s\n", text)
			continue
		}
		authorStr := types.ToString(author)

		if *listCvesInReverse {
			name := infoMap["name"]
			author := infoMap["author"]
			severity := infoMap["severity"]
			if strings.HasPrefix(fmt.Sprintf("%v", id), "CVE-") {
				cveList = append(cveList, CveItem{CveID: fmt.Sprintf("%v", id), Name: fmt.Sprintf("%v", name), Author: fmt.Sprintf("%v", author), Severity: fmt.Sprintf("%v", severity)})
			} else {
				nonCveList = append(nonCveList, NonCveItem{Id: fmt.Sprintf("%v", id), Name: fmt.Sprintf("%v", name), Author: fmt.Sprintf("%v", author), Severity: fmt.Sprintf("%v", severity)})
			}
			continue
		}
		_, _ = output.WriteString("- " + text + " by " + explodeAuthorsAndJoin(authorStr) + "\n")
	}

	if len(cveList) > 0 {
		sort.Sort(cveList)
		hasTopFilter := *count > 0
		if hasTopFilter && len(cveList) > *count {
			cveList = cveList[:*count]
		}
		fields := strings.Split(*includeFields, ",")
		fields = sliceutil.Dedupe(fields)
		for _, cve := range cveList {
			_, _ = output.WriteString(formatCveItem(cve, fields))
		}
		*count = *count - len(cveList)
		if hasTopFilter && *count >= 0 {
			nonCveList = nonCveList[:*count]
		}
		for _, nc := range nonCveList {
			_, _ = output.WriteString(formatNonCveItem(nc, fields))
		}
		os.Exit(0)
	}
	return nil
}

func explodeAuthorsAndJoin(author string) string {
	if !strings.Contains(author, ",") {
		if strings.HasPrefix(author, "@") {
			return author
		}
		return "@" + author
	}

	parts := strings.Split(author, ",")
	partValues := make([]string, 0, len(parts))
	for _, part := range parts {
		if strings.HasPrefix(part, "@") {
			partValues = append(partValues, part)
		}
		partValues = append(partValues, "@"+part)
	}
	return strings.Join(partValues, ",")
}

func explodeCommaSeparatedField(field string) []string {
	if !strings.Contains(field, ",") {
		return []string{strings.ToLower(field)}
	}

	parts := strings.Split(field, ",")
	partValues := make([]string, 0, len(parts))
	for _, part := range parts {
		partValues = append(partValues, strings.ToLower(strings.TrimSpace(part)))
	}
	return partValues
}

func formatCveItem(cveItem CveItem, fields []string) string {
	text := fmt.Sprintf("[%s] %s", cveItem.CveID, cveItem.Name)
	if len(fields) == 0 {
		return text + "\n"
	}
	for _, field := range fields {
		switch field {
		case "author":
			authors := strings.Split(cveItem.Author, ",")
			a := ""
			for i, author := range authors {
				a += "@" + author
				if i+1 != len(authors) {
					a += ", "
				}
			}
			text = fmt.Sprintf("%s (%s)", text, a)
		case "severity":
			text = fmt.Sprintf("%s [%s]", text, cveItem.Severity)
		}
	}
	return text + "\n"
}

func formatNonCveItem(nc NonCveItem, fields []string) string {
	text := fmt.Sprintf("[%s] %s", nc.Id, nc.Name)
	if len(fields) == 0 {
		return text + "\n"
	}
	for _, field := range fields {
		switch field {
		case "author":
			authors := strings.Split(nc.Author, ",")
			a := ""
			for i, author := range authors {
				a += "@" + author
				if i+1 != len(authors) {
					a += ", "
				}
			}
			text = fmt.Sprintf("%s (%s)", text, a)
		case "severity":
			text = fmt.Sprintf("%s [%s]", text, nc.Severity)
		}
	}
	return text + "\n"
}
