package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/dghubble/sling"
	"github.com/zachmann/liboidcagent-go/liboidcagent"

	"gopkg.in/alecthomas/kingpin.v2"
)

const wattsonVersion string = "1.2.3"

var (
	app     = kingpin.New("wattson", "The WaTTS client.\n \nPlease store your issuer id (up to version 1 the issuer url) in the 'WATTSON_ISSUER' environment variable:\n export WATTSON_ISSUER=<the issuer id> \nThe url of WaTTS can be stored in the environment variable 'WATTSON_URL':\n export WATTSON_URL=<url of watts>\n\nIt is possible to either pass the access token directly to wattson or use oidc-agent to retrieve access tokens.\nTo use oidc-agent the environment variable 'OIDC_SOCK' needs to point to the socket of the agent and 'WATTSON_AGENT_ACCOUNT' needs to contain the oidc-agent account name to use, the account needs to be loaded, else it will fail: \n export OIDC_SOCK=<path to the oidc-agent socket> (usually this is already exported) \n export WATTSON_AGENT_ACCOUNT=<account of oidc-agent to use> \n \nIf you want to pass the access token directly please use the WATTSON_TOKEN variable: \n export WATTSON_TOKEN=<access token>\n \n").Version(wattsonVersion)
	hostUrl = app.Flag("url", "the base url of watts' rest interface").Short('u').String()

	protVersion = app.Flag("protver", "protocol version to use (can be 0, 1 or 2)").Default("2").Short('p').Int()
	jsonOutput  = app.Flag("json", "enable json output").Short('j').Bool()
	debugOutput = app.Flag("debug", "enable debug output").Bool()
	wattsInfo   = app.Command("info", "get the information about watts, e.g. its version")

	lsProv = app.Command("lsprov", "list all OpenID Connect provider")

	lsService = app.Command("lsserv", "list all service")

	lsCred = app.Command("lscred", "list all credentials")

	request       = app.Command("request", "request a credential for a service")
	requestId     = request.Arg("serviceId", "the id of the service to request a credential").Required().String()
	requestParams = request.Arg("parameter", "a string containing a json object with the parameter").String()

	revoke       = app.Command("revoke", "revoke a credential")
	revokeCredId = revoke.Arg("credId", "the id of the credential to revoke").Required().String()
)

type WattsError struct {
	Result  string `json:"result"`
	Message string `json:"user_msg"`
}

func (e WattsError) Error() string {
	output := ""
	if is_error(&e) {
		if *jsonOutput {
			json, _ := json.Marshal(e)
			output = string(json)
		} else {
			output = fmt.Sprintf("Error: %s", e.Message)
		}
	}
	return output
}

func is_error(e *WattsError) bool {
	return e.Result == "error"
}

type WattsInfo struct {
	Name         string `json:"display_name"`
	LoggedIn     bool   `json:"logged_in"`
	RedirectPath string `json:"redirect_path"`
	Version      string `json:"version"`
}

func (info WattsInfo) String() string {
	output := ""
	if *jsonOutput {
		json, _ := json.Marshal(info)
		output = string(json)
	} else {
		output = output + fmt.Sprintf("watts version: %s\n", info.Version)
		output = output + fmt.Sprintf("  the redirect path is: %s\n", info.RedirectPath)
		if info.LoggedIn {
			output = output + fmt.Sprintf("this connection is logged in as %s\n", info.Name)
		} else {
			output = output + fmt.Sprintln("this connection is *NOT* logged in")
		}
	}
	return output
}

type WattsProvider struct {
	Id     string `json:"id"`
	Issuer string `json:"issuer"`
	Desc   string `json:"desc"`
	Ready  bool   `json:"ready"`
}

func (prov WattsProvider) String() string {
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

type WattsProviderList struct {
	Provider []WattsProvider `json:"openid_provider_list"`
}

func (provList WattsProviderList) String() string {
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

type WattsServiceParam struct {
	Key       string `json:"key"`
	Name      string `json:"name"`
	Desc      string `json:"description"`
	Type      string `json:"type"`
	Mandatory bool   `json:"mandatory"`
}

func (param WattsServiceParam) String() string {
	must := "Optional"
	if param.Mandatory {
		must = "MANDATORY"
	}
	output := fmt.Sprintf("%s Parameter '%s' [%s]: %s (%s)\n", must, param.Name, param.Key, param.Desc, param.Type)
	return output
}

type WattsService struct {
	Id           string                `json:"id"`
	Desc         string                `json:"description"`
	Type         string                `json:"type"`
	Host         string                `json:"host"`
	Port         string                `json:"port"`
	CredCount    int                   `json:"cred_count"`
	CredLimit    int                   `json:"cred_limit"`
	LimitReached bool                  `json:"limit_reached"`
	Enabled      bool                  `json:"enabled"`
	Authorized   bool                  `json:"authorized"`
	PassAT       bool                  `json:"pass_access_token"`
	Tooltip      string                `json:"authz_tooltip"`
	Params       [][]WattsServiceParam `json:"params"`
}

func (serv WattsService) String() string {
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
	icons := " "
	if serv.PassAT {
		icons = icons + "AT! "
	}
	reached := ""
	if serv.LimitReached {
		reached = "(limit reached)"
	}
	if *protVersion == 2 {
		output = fmt.Sprintf("Service [%s][%s/%s] [%s] %s\n", serv.Id, on, auth, icons, serv.Desc)
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

type WattsServiceList struct {
	Services []WattsService `json:"service_list"`
}

func (servList WattsServiceList) String() string {
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

type WattsonCredentialEntry struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

func (entry WattsonCredentialEntry) String() string {
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

type WattsonCredential struct {
	Id        string                   `json:"id"`
	InfoId    string                   `json:"cred_id"`
	CTime     string                   `json:"ctime"`
	Interface string                   `json:"interface"`
	ServiceId string                   `json:"service_id"`
	Entries   []WattsonCredentialEntry `json:"entries"`
}

func (cred WattsonCredential) String() string {
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

type WattsonCredentialResult struct {
	Credential WattsonCredential `json:"credential"`
}

func (res WattsonCredentialResult) String() string {
	output := ""
	if *jsonOutput {
		json, _ := json.Marshal(res)
		output = string(json)
	} else {
		output = fmt.Sprintln(res.Credential.String())
	}
	return output
}

type WattsonCredentialListV1 struct {
	Credentials []TtsV1CredWrap `json:"credential_list"`
}
type WattsonCredentialListV2 struct {
	Credentials []WattsonCredential `json:"credential_list"`
}

func (credList WattsonCredentialListV2) String() string {
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

func (credList WattsonCredentialListV1) String() string {
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

type WattsonCredentialRequest struct {
	ServiceId string                   `json:"service_id"`
	Params    (map[string]interface{}) `json:"params"`
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
	_, set := os.LookupEnv("WATTSON_INSECURE")
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

func watts_info(base *sling.Sling) {
	info := new(WattsInfo)
	wattsError := new(WattsError)
	if !*jsonOutput {
		fmt.Println("retrieving information:")
	}
	resp, err := base.Get("./info").Receive(info, wattsError)
	if err != nil {
		fmt.Printf("error requesting information:\n %s\n", err)
		return
	}
	display_response(resp)
	if is_error(wattsError) {
		fmt.Printf("error requesting information:\n %s\n", wattsError)
	} else {
		fmt.Println(info)
	}
}

func provider_list(base *sling.Sling) {
	providerList := new(WattsProviderList)
	wattsError := new(WattsError)
	if !*jsonOutput {
		fmt.Println("retrieving provider list:")
	}
	resp, err := base.Get("./oidcp").Receive(providerList, wattsError)
	if err != nil {
		fmt.Printf("error requesting list of provider:\n %s\n", err)
		return
	}
	display_response(resp)
	if is_error(wattsError) {
		fmt.Printf("error requesting list of provider:\n %s\n", wattsError)
	} else {
		fmt.Println(providerList)
	}
}

func service_list(base *sling.Sling) {
	serviceList := new(WattsServiceList)
	wattsError := new(WattsError)
	if !*jsonOutput {
		fmt.Println("retrieving service list:")
	}
	resp, err := base.Get("./service").Receive(serviceList, wattsError)
	if err != nil {
		fmt.Printf("error requesting list of services:\n %s\n", err)
		return
	}
	display_response(resp)
	if is_error(wattsError) {
		fmt.Printf("error requesting list of services:\n %s\n", wattsError)
	} else {
		fmt.Println(serviceList)
	}
}

func credential_list(base *sling.Sling) {
	ListV2 := new(WattsonCredentialListV2)
	ListV1 := new(WattsonCredentialListV1)
	wattsError := new(WattsError)

	if !*jsonOutput {
		fmt.Println("retrieving credential list:")
	}
	if *protVersion == 2 {
		resp, err := base.Get("./credential").Receive(ListV2, wattsError)
		if err != nil {
			fmt.Printf("error requesting list of credentials:\n %s\n", err)
			return
		}
		display_response(resp)
		if is_error(wattsError) {
			fmt.Printf("error requesting list of credentials:\n %s\n", wattsError)
		} else {
			fmt.Println(ListV2)
		}
	} else {
		resp, err := base.Get("./credential").Receive(ListV1, wattsError)
		if err != nil {
			fmt.Printf("error requesting list of credentials:\n %s\n", err)
			return
		}
		display_response(resp)
		if is_error(wattsError) {
			fmt.Printf("error requesting list of credentials:\n %s\n", wattsError)
		} else {
			fmt.Println(ListV1)
		}
	}
}

func credential_request(serviceId string, parameter string, base *sling.Sling) {
	credential := new(WattsonCredentialResult)
	oldCred := new([]WattsonCredentialEntry)
	wattsError := new(WattsError)
	var parameterMap map[string]interface{}

	if parameter == "" {
		parameter = "{}"
	}

	paramErr := json.Unmarshal([]byte(parameter), &parameterMap)
	if paramErr != nil {
		fmt.Printf("error parsing the parameter: %s\n", paramErr)
		return
	}
	if !*jsonOutput {
		fmt.Printf("requesting credential for service [%s]:\n", serviceId)
	}

	body := &WattsonCredentialRequest{
		ServiceId: serviceId,
		Params:    parameterMap,
	}

	if *protVersion == 2 {
		resp, err := base.Post("./credential").BodyJSON(body).Receive(credential, wattsError)
		if err != nil {
			fmt.Printf("error requesting of credential:\n %s\n", err)
			return
		}
		display_response(resp)
		if is_error(wattsError) {
			fmt.Printf("error requesting of credential (at watts):\n %s\n", wattsError)
		} else {
			fmt.Println(credential)
		}
	} else {
		resp, err := base.Post("./credential").BodyJSON(body).Receive(oldCred, wattsError)
		if err != nil {
			fmt.Printf("error requesting of credential:\n %s\n", err)
			return
		}
		display_response(resp)
		if is_error(wattsError) {
			fmt.Printf("error requesting of credential:\n %s\n", wattsError)
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
			fmt.Println("{\"result\":\"ok\"}")
		}

	}
}

func get_issuer_account() (issuerSet bool, issuerValue string, agentIssuer string) {
	agentAccount, accountSet := os.LookupEnv("WATTSON_AGENT_ACCOUNT")
	issuerValue, issuerSet = os.LookupEnv("WATTSON_ISSUER")
	if !accountSet && issuerSet {
		agentAccount = issuerValue
	}
	if !issuerSet && (!*jsonOutput) {
		fmt.Println("*** WARNING: no issuer has been provided ***")
		agentIssuer = ""
		issuerValue = ""
	}
	return issuerSet, issuerValue, agentAccount
}

func user_info(format string, a ...interface{}) {
	if !*jsonOutput {
		fmt.Printf(format, a)
	}
}

func try_agent_token(account string) (tokenSet bool, tokenValue string) {
	token, err := liboidcagent.GetAccessToken(account, 120, "", "wattson")
	if err != nil {
		return false, tokenValue
	}
	return true, token
}

func try_token(issuer string) (tokenSet bool, token string) {
	tokenValue, tokenSet := os.LookupEnv("WATTSON_TOKEN")
	if !tokenSet {
		return try_agent_token(issuer)
	}
	return tokenSet, tokenValue
}

func base_connection(urlBase string) *sling.Sling {
	client := client()
	issuerSet, issuerValue, agentAccount := get_issuer_account()
	tokenSet, tokenValue := try_token(agentAccount)
	base := sling.New().Client(client).Base(urlBase)
	base = base.Set("User-Agent", "Wattson")
	base = base.Set("Accept", "application/json")
	if tokenSet && issuerSet {
		token := "Bearer " + tokenValue
		base = base.Set("Authorization", token)
		if *protVersion <= 1 {
			base = base.Set("X-OpenId-Connect-Issuer", issuerValue)
		}
	}
	return base
}

func base_url(rawUrl string) string {
	issuerValue, issuerSet := os.LookupEnv("WATTSON_ISSUER")
	apiPath := "v2/"
	if issuerSet {
		apiPath = "v2/" + issuerValue + "/"
	}
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
	urlValue, urlSet := os.LookupEnv("WATTSON_URL")
	baseUrl := ""
	if *hostUrl != "" {
		baseUrl = base_url(*hostUrl)
	} else if urlSet {
		baseUrl = base_url(urlValue)
	} else {
		fmt.Println("*** ERROR: No url given! Either set the environment varible 'WATTSON_URL' or use the --url flag")
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
	case wattsInfo.FullCommand():
		base := connection()
		watts_info(base)
	case lsProv.FullCommand():
		base := connection()
		provider_list(base)

	case lsService.FullCommand():
		base := connection()
		service_list(base)

	case lsCred.FullCommand():
		base := connection()
		credential_list(base)

	case request.FullCommand():
		base := connection()
		credential_request(*requestId, *requestParams, base)

	case revoke.FullCommand():
		base := connection()
		credential_revoke(*revokeCredId, base)
	}
}
