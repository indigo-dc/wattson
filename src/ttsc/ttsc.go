package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/dghubble/sling"
	"gopkg.in/alecthomas/kingpin.v2"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
)

const ttscVersion string = "1.0.0-alpha"

var (
	app     = kingpin.New("ttsc", "The Token Translation Service (TTS) client.\nPlease store your access token in the 'TTSC_TOKEN' and the issuer url in the 'TTSC_ISSUER' environment variable: 'export TTSC_TOKEN=<your access token>', 'export TTSC_ISSUER=<the issuer url>'. The url of the TTS can be stored in the environment variable 'TTSC_URL': export TTSC_URL=<url of the tts>").Version(ttscVersion)
	hostUrl = app.Flag("url", "the base url of the TTS rest interface").Short('u').String()

	protVersion = app.Flag("protver", "protocol version to use (can be 0, 1 or 2)").Default("2").Short('p').Int()
	jsonOutput  = app.Flag("json", "enable json output").Short('j').Bool()
	debugOutput = app.Flag("debug", "enable debug output").Bool()
	ttsInfo     = app.Command("info", "get the information about the TTS running, e.g. its version")

	lsProv = app.Command("lsprov", "list all OpenID Connect provider")

	lsService = app.Command("lsserv", "list all service")

	lsCred = app.Command("lscred", "list all credentials")

	basicRequest   = app.Command("request", "request a credential for a service")
	basicRequestId = basicRequest.Arg("serviceId", "the id of the service to request a credential").Required().String()

	revoke       = app.Command("revoke", "revoke a credential")
	revokeCredId = revoke.Arg("credId", "the id of the credential to revoke").Required().String()
)

type TtsError struct {
	Result  string `json:"result"`
	Message string `json:"user_msg"`
}

func (e TtsError) Error() string {
	if is_error(&e) {
		return fmt.Sprintf("Error: %s", e.Message)
	} else {
		return ""
	}
}

func is_error(e *TtsError) bool {
	return e.Result == "error"
}

type TtsInfo struct {
	Name         string `json:"display_name"`
	LoggedIn     bool   `json:"logged_in"`
	RedirectPath string `json:"redirect_path"`
	Version      string `json:"version"`
}

func (info TtsInfo) String() string {
	output := ""
	if *jsonOutput {
		json, _ := json.Marshal(info)
		output = string(json)
	} else {
		output = output + fmt.Sprintf("TTS version: %s\n", info.Version)
		output = output + fmt.Sprintf("  the redirect path is: %s\n", info.RedirectPath)
		if info.LoggedIn {
			output = output + fmt.Sprintf("this connection is logged in as %s\n", info.Name)
		} else {
			output = output + fmt.Sprintln("this connection is *NOT* logged in")
		}
	}
	return output
}

type TtsProvider struct {
	Id     string `json:"id"`
	Issuer string `json:"issuer"`
	Desc   string `json:"desc"`
	Ready  bool   `json:"ready"`
}

func (prov TtsProvider) String() string {
	output := ""
	if *jsonOutput {
		json, _ := json.Marshal(prov)
		output = string(json)
	} else {
		ready := "NOT READY"
		if prov.Ready {
			ready = "ready"
		}
		if *protVersion == 2 {
			output = fmt.Sprintf("Provider [%s][%s] %s (%s)", prov.Id, ready, prov.Desc, prov.Issuer)
		} else {
			output = fmt.Sprintf("Provider [%s] %s", prov.Id, prov.Issuer)
		}
	}
	return output
}

type TtsProviderList struct {
	Provider []TtsProvider `json:"openid_provider_list"`
}

func (provList TtsProviderList) String() string {
	output := ""
	if *jsonOutput {
		json, _ := json.Marshal(provList)
		output = string(json)
	} else {
		for _, provider := range provList.Provider {
			output = output + fmt.Sprintln(provider)
		}
	}
	return output
}

type TtsServiceParam struct {
	Key       string `json:"key"`
	Name      string `json:"name"`
	Desc      string `json:"description"`
	Type      string `json:"type"`
	Mandatory bool   `json:"mandatory"`
}

func (param TtsServiceParam) String() string {
	must := "Optional"
	if param.Mandatory {
		must = "MANDATORY"
	}
	output := fmt.Sprintf("%s Parameter '%s' [%s]: %s (%s)\n", must, param.Name, param.Key, param.Desc, param.Type)
	return output
}

type TtsService struct {
	Id           string              `json:"id"`
	Desc         string              `json:"description"`
	Type         string              `json:"type"`
	Host         string              `json:"host"`
	Port         string              `json:"port"`
	CredCount    int                 `json:"cred_count"`
	CredLimit    int                 `json:"cred_limit"`
	LimitReached bool                `json:"limit_reached"`
	Enabled      bool                `json:"enabled"`
	Authorized   bool                `json:"authorized"`
	Tooltip      string              `json:"authz_tooltip"`
	Params       [][]TtsServiceParam `json:"params"`
}

func (serv TtsService) String() string {
	output := ""
	on := "disabled"
	if serv.Enabled {
		on = "enabled"
	}
	auth := "NOT AUTHORIZED"
	tooltip := serv.Tooltip
	if serv.Authorized {
		auth = "authorized"
		tooltip = ""
	}
	reached := ""
	if serv.LimitReached {
		reached = "(limit reached)"
	}
	if *protVersion == 2 {
		output = fmt.Sprintf("Service [%s][%s/%s] %s\n", serv.Id, on, auth, serv.Desc)
		if tooltip != "" {
			output = output + fmt.Sprintf("   %s\n", tooltip)
		}
		output = output + fmt.Sprintf(" - credenitals: %d/%d %s\n", serv.CredCount, serv.CredLimit, reached)
		if len(serv.Params) == 0 {
			output = output + fmt.Sprintf(" - service has no parameter\n")
		} else {
			output = output + fmt.Sprintf(" - parameter sets:\n")
			for _, set := range serv.Params {
				if len(set) == 0 {
					output = output + fmt.Sprintln("    Empty Parameter Set (allows basic request)")
				} else {
					output = output + fmt.Sprintln("    Parameter Set:")
					for _, param := range set {
						output = output + fmt.Sprintf("      %s\n", param)
					}
				}
			}
		}
	} else {
		output = fmt.Sprintf("Service [%s] %s - %s:%s", serv.Id, serv.Type, serv.Host, serv.Port)
	}
	return output
}

type TtsServiceList struct {
	Services []TtsService `json:"service_list"`
}

func (servList TtsServiceList) String() string {
	output := ""
	if *jsonOutput {
		json, _ := json.Marshal(servList)
		output = string(json)
	} else {
		output = "\n"
		for _, service := range servList.Services {
			output = output + fmt.Sprintln(service)
			output = output + fmt.Sprintln("")
		}
	}
	return output
}

type TtsCredentialEntry struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

func (entry TtsCredentialEntry) String() string {
	output := fmt.Sprintf("[ %s (%s)] => %s", entry.Name, entry.Type, entry.Value)
	return output
}

type TtsV1Credential struct {
	Id        string `json:"cred_id"`
	CredState string `json:"cred_state"`
	CTime     string `json:"ctime"`
	Interface string `json:"interface"`
	ServiceId string `json:"service_id"`
}
type TtsV1CredWrap struct {
	Credential TtsV1Credential `json:"id"`
}

func (credWrap TtsV1CredWrap) String() string {
	output := ""
	cred := credWrap.Credential
	output = fmt.Sprintf("Credential [%s]{%s}: for service with id [%s] created %s at '%s'", cred.Id, cred.CredState, cred.ServiceId, cred.CTime, cred.Interface)
	return output
}

type TtsCredential struct {
	Id        string               `json:"id"`
	InfoId    string               `json:"cred_id"`
	CTime     string               `json:"ctime"`
	Interface string               `json:"interface"`
	ServiceId string               `json:"service_id"`
	Entries   []TtsCredentialEntry `json:"entries"`
}

func (cred TtsCredential) String() string {
	output := ""
	if cred.Id == "" && *protVersion == 2 {
		output = fmt.Sprintf("Credential [%s]: for service with id [%s] created %s at '%s'", cred.InfoId, cred.ServiceId, cred.CTime, cred.Interface)
	} else {
		if *protVersion == 2 {
			output = fmt.Sprintf("Credential [%s]:\n", cred.Id)
		} else {
			output = fmt.Sprintln("Credential:")
		}
		for _, entry := range cred.Entries {
			output = output + fmt.Sprintf("%s\n", entry)
		}

	}
	return output
}

type TtsCredentialResult struct {
	Credential TtsCredential `json:"credential"`
}

func (res TtsCredentialResult) String() string {
	output := ""
	if *jsonOutput {
		json, _ := json.Marshal(res)
		output = string(json)
	} else {
		output = fmt.Sprintln(res.Credential.String())
	}
	return output
}

type TtsCredentialListV1 struct {
	Credentials []TtsV1CredWrap `json:"credential_list"`
}
type TtsCredentialListV2 struct {
	Credentials []TtsCredential `json:"credential_list"`
}

func (credList TtsCredentialListV2) String() string {
	output := ""
	if *jsonOutput {
		json, _ := json.Marshal(credList)
		output = string(json)
	} else {
		output = "\n"
		if len(credList.Credentials) == 0 {
			output = "*** no credentials ***"
		} else {
			for _, cred := range credList.Credentials {
				output = output + fmt.Sprintln(cred)
			}
			output = output + "\n"
		}
	}
	return output
}

func (credList TtsCredentialListV1) String() string {
	output := ""
	if *jsonOutput {
		json, _ := json.Marshal(credList)
		output = string(json)
	} else {
		output = "\n"
		if len(credList.Credentials) == 0 {
			output = "*** no credentials ***"
		} else {
			for _, cred := range credList.Credentials {
				output = output + fmt.Sprintln(cred)
			}
			output = output + "\n"
		}
	}
	return output
}

type TtsCredentialRequest struct {
	ServiceId string `json:"service_id"`
}

func copy_header(Name string) bool {
	CopyHeader := []string{"User-Agent", "Authorization", "X-Openid-Connect-Issuer"}
	for _, h := range CopyHeader {
		if Name == h {
			return true
		}
	}
	return false
}

func redirect_check(req *http.Request, via []*http.Request) error {
	Header := via[0].Header
	ReqHeader := req.Header
	for key, value := range Header {
		if copy_header(key) {
			ReqHeader.Set(key, value[0])
		}
	}
	req.Header = ReqHeader
	return nil
}

func client() *http.Client {
	_, set := os.LookupEnv("TTSC_INSECURE")
	client := http.DefaultClient
	if set {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client = &http.Client{Transport: tr}
	}
	client.CheckRedirect = redirect_check
	return client
}

func tts_info(base *sling.Sling) {
	info := new(TtsInfo)
	ttsError := new(TtsError)
	if !*jsonOutput {
		fmt.Println("retrieving information:")
	}
	resp, err := base.Get("./info").Receive(info, ttsError)
	if err != nil {
		fmt.Printf("error requesting information:\n %s\n", err)
		return
	}
	display_response(resp)
	if is_error(ttsError) {
		fmt.Printf("error requesting information:\n %s\n", ttsError)
	} else {
		fmt.Println(info)
	}
}

func provider_list(base *sling.Sling) {
	providerList := new(TtsProviderList)
	ttsError := new(TtsError)
	if !*jsonOutput {
		fmt.Println("retrieving provider list:")
	}
	resp, err := base.Get("./oidcp").Receive(providerList, ttsError)
	if err != nil {
		fmt.Printf("error requesting list of provider:\n %s\n", err)
		return
	}
	display_response(resp)
	if is_error(ttsError) {
		fmt.Printf("error requesting list of provider:\n %s\n", ttsError)
	} else {
		fmt.Println(providerList)
	}
}

func service_list(base *sling.Sling) {
	serviceList := new(TtsServiceList)
	ttsError := new(TtsError)
	if !*jsonOutput {
		fmt.Println("retrieving service list:")
	}
	resp, err := base.Get("./service").Receive(serviceList, ttsError)
	if err != nil {
		fmt.Printf("error requesting list of services:\n %s\n", err)
		return
	}
	display_response(resp)
	if is_error(ttsError) {
		fmt.Printf("error requesting list of services:\n %s\n", ttsError)
	} else {
		fmt.Println(serviceList)
	}
}

func credential_list(base *sling.Sling) {
	ListV2 := new(TtsCredentialListV2)
	ListV1 := new(TtsCredentialListV1)
	ttsError := new(TtsError)

	if !*jsonOutput {
		fmt.Println("retrieving credential list:")
	}
	if *protVersion == 2 {
		resp, err := base.Get("./credential").Receive(ListV2, ttsError)
		if err != nil {
			fmt.Printf("error requesting list of credentials:\n %s\n", err)
			return
		}
		display_response(resp)
		if is_error(ttsError) {
			fmt.Printf("error requesting list of credentials:\n %s\n", ttsError)
		} else {
			fmt.Println(ListV2)
		}
	} else {
		resp, err := base.Get("./credential").Receive(ListV1, ttsError)
		if err != nil {
			fmt.Printf("error requesting list of credentials:\n %s\n", err)
			return
		}
		display_response(resp)
		if is_error(ttsError) {
			fmt.Printf("error requesting list of credentials:\n %s\n", ttsError)
		} else {
			fmt.Println(ListV1)
		}
	}
}

func credential_basic_request(serviceId string, base *sling.Sling) {
	credential := new(TtsCredentialResult)
	oldCred := new([]TtsCredentialEntry)
	ttsError := new(TtsError)

	if !*jsonOutput {
		fmt.Printf("requesting credential for service [%s]:\n", serviceId)
	}
	body := &TtsCredentialRequest{
		ServiceId: serviceId,
	}

	if *protVersion == 2 {
		resp, err := base.Post("./credential").BodyJSON(body).Receive(credential, ttsError)
		if err != nil {
			fmt.Printf("error requesting of credential:\n %s\n", err)
			return
		}
		display_response(resp)
		if is_error(ttsError) {
			fmt.Printf("error requesting of credential (TTS):\n %s\n", ttsError)
		} else {
			fmt.Println(credential)
		}
	} else {
		resp, err := base.Post("./credential").BodyJSON(body).Receive(oldCred, ttsError)
		if err != nil {
			fmt.Printf("error requesting of credential:\n %s\n", err)
			return
		}
		display_response(resp)
		if is_error(ttsError) {
			fmt.Printf("error requesting of credential:\n %s\n", ttsError)
		} else {
			credential.Credential.Entries = *oldCred
			fmt.Println(credential)
		}
	}

}

func credential_revoke(credId string, base *sling.Sling) {
	if !*jsonOutput {
		fmt.Printf("revoking credential [%s]:\n", credId)
	}
	path := fmt.Sprintf("./credential/%s", credId)
	resp, err := base.Delete(path).Receive(nil, nil)
	if err != nil {
		fmt.Printf("error revoking of credential:\n %s\n", err)
		return
	} else {
		display_response(resp)
		if !*jsonOutput {
			fmt.Println("credential sucessfully revoked")
		} else {
			fmt.Println("{'result':'ok'}")
		}

	}
}

func base_connection(urlBase string) *sling.Sling {
	client := client()
	tokenValue, tokenSet := os.LookupEnv("TTSC_TOKEN")
	issuerValue, issuerSet := os.LookupEnv("TTSC_ISSUER")
	base := sling.New().Client(client).Base(urlBase)
	base = base.Set("User-Agent", "TTSc")
	base = base.Set("Accept", "application/json")
	if tokenSet && issuerSet {
		token := "Bearer " + tokenValue
		return base.Set("Authorization", token).Set("X-OpenId-Connect-Issuer", issuerValue)
	} else {
		fmt.Println(" ")
		fmt.Println("*** WARNING: either access token or issuer has not been specified ***")
		fmt.Println(" ")
		return base
	}
}

func base_url(rawUrl string) string {
	apiPath := "v2/"
	if *protVersion == 0 {
		apiPath = ""
	} else if *protVersion == 1 {
		apiPath = "v1/"
	}
	if !strings.HasSuffix(rawUrl, "/") {
		rawUrl = rawUrl + "/"
	}
	u, _ := url.Parse(rawUrl)
	urlBase := u.Scheme + "://" + u.Host + u.Path + "api/" + apiPath
	if !*jsonOutput {
		fmt.Printf("connecting to %s using protocol version %d \n", urlBase, *protVersion)
	}
	return urlBase
}

func display_response(resp *http.Response) {
	if *debugOutput {
		fmt.Printf("DEBUG: %s\n", *resp)
		body, _ := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		fmt.Printf("DEBUG: %s\n", body)
	}
}

func get_base_url() string {
	urlValue, urlSet := os.LookupEnv("TTSC_URL")
	baseUrl := ""
	if *hostUrl != "" {
		baseUrl = base_url(*hostUrl)
	} else if urlSet {
		baseUrl = base_url(urlValue)
	} else {
		fmt.Println("*** ERROR: No url given! Either set the environment varible 'TTSC_URL' or use the --url flag")
		os.Exit(1)
	}
	return baseUrl
}

func connection() *sling.Sling {
	baseurl := get_base_url()
	conn := base_connection(baseurl)
	return conn
}

func main() {
	switch kingpin.MustParse(app.Parse(os.Args[1:])) {
	case ttsInfo.FullCommand():
		base := connection()
		tts_info(base)
	case lsProv.FullCommand():
		base := connection()
		provider_list(base)

	case lsService.FullCommand():
		base := connection()
		service_list(base)

	case lsCred.FullCommand():
		base := connection()
		credential_list(base)

	case basicRequest.FullCommand():
		base := connection()
		credential_basic_request(*basicRequestId, base)

	case revoke.FullCommand():
		base := connection()
		credential_revoke(*revokeCredId, base)
	}
}
