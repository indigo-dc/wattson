package main

import (
	// "bufio"
	"crypto/tls"
	// "encoding/json"
	"fmt"
	"github.com/dghubble/sling"
	"gopkg.in/alecthomas/kingpin.v2"
	"net/http"
	"net/url"
	"os"
	"strings"
)

const ttscVersion string = "1.0.0-alpha"
const apiVersion string = "v2"

var (
	app     = kingpin.New("ttsc", "The Token Translation Service (TTS) client.\nPlease store your access token in the 'TTSC_TOKEN' and the issuer url in the 'TTS_ISSUER' environment variable: 'export TTSC_TOKEN=<your access token>', 'export TTSC_ISSUER=<the issuer url>'").Version(ttscVersion)
	hostUrl = app.Flag("url", "the base url of the TTS rest interface").Short('u').Required().String()

	ttsInfo = app.Command("info", "get the information about the TTS running, e.g. its version")

	lsProv = app.Command("lsprov", "list all OpenID Connect provider")

	lsService = app.Command("lsserv", "list all service")

	lsCred = app.Command("lscred", "list all credentials")

	basicRequest   = app.Command("request", "request a credential for a service")
	basicRequestId = basicRequest.Arg("serviceId", "the id of the service to request a credential").Required().String()

	revoke       = app.Command("revoke", "revoke a credential")
	revokeCredId = revoke.Arg("credId", "the id of the credential to revoke").Required().String()
)

type TtsError struct {
	Code    int    `json:"code"`
	Title   string `json:"error"`
	Message string `json:"message"`
}

func (e TtsError) Error() string {
	if e.Title != "" || e.Message != "" {
		return fmt.Sprintf("Error '%s' [%d]: %s", e.Title, e.Code, e.Message)
	} else {
		return ""
	}
}

func is_error(e *TtsError) bool {
	return e.Error() != ""
}

type TtsInfo struct {
	Name         string `json:"display_name"`
	LoggedIn     bool   `json:"logged_in"`
	RedirectPath string `json:"redirect_path"`
	Version      string `json:"version"`
}

func (info TtsInfo) String() string {
	output := ""
	output = output + fmt.Sprintf("TTS version: %s\n", info.Version)
	output = output + fmt.Sprintf("  the redirect path is: %s\n", info.RedirectPath)
	if info.LoggedIn {
		output = output + fmt.Sprintf("this connection is logged in as %s\n", info.Name)
	} else {
		output = output + fmt.Sprintln("this connection is *NOT* logged in")
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
	ready := "NOT READY"
	if prov.Ready {
		ready = "ready"
	}
	output := fmt.Sprintf("Provider [%s][%s] %s (%s)", prov.Id, ready, prov.Desc, prov.Issuer)
	return output
}

type TtsProviderList struct {
	Provider []TtsProvider `json:"openid_provider_list"`
}

func (provList TtsProviderList) String() string {
	output := ""
	for _, provider := range provList.Provider {
		output = output + fmt.Sprintln(provider)
	}
	return output
}

type TtsServiceParam struct {
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
	output := fmt.Sprintf("%s Parameter [%s](%s): %s \n", must, param.Name, param.Type, param.Desc)
	return output
}

type TtsService struct {
	Id           string            `json:"id"`
	Desc         string            `json:"description"`
	Type         string            `json:"type"`
	Host         string            `json:"host"`
	Port         string            `json:"port"`
	CredCount    int               `json:"cred_count"`
	CredLimit    int               `json:"cred_limit"`
	LimitReached bool              `json:"limit_reached"`
	Enabled      bool              `json:"enabled"`
	Params       []TtsServiceParam `json:"params"`
}

func (serv TtsService) String() string {
	on := "disabled"
	if serv.Enabled {
		on = "enabled"
	}
	reached := ""
	if serv.LimitReached {
		reached = "(limit reached)"
	}
	output := fmt.Sprintf("Service [%s][%s] %s\n", serv.Id, on, serv.Desc)
	output = output + fmt.Sprintf(" - credenitals: %d/%d %s\n", serv.CredCount, serv.CredLimit, reached)
	if len(serv.Params) == 0 {
		output = output + fmt.Sprintf(" - service has no parameter\n")
	} else {
		output = output + fmt.Sprintf(" - parameter:\n")
		for _, param := range serv.Params {
			output = output + fmt.Sprintf("    %s\n", param)
		}

	}
	return output
}

type TtsServiceList struct {
	Services []TtsService `json:"service_list"`
}

func (servList TtsServiceList) String() string {
	output := "\n"
	for _, service := range servList.Services {
		output = output + fmt.Sprintln(service)
		output = output + fmt.Sprintln("")
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
	if cred.Id == "" {
		output = fmt.Sprintf("Credential [%s]: for service with id [%s] created %s at '%s'", cred.InfoId, cred.ServiceId, cred.CTime, cred.Interface)
	} else {
		output = fmt.Sprintf("Credential [%s]:\n", cred.Id)
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
	output := fmt.Sprintln(res.Credential.String())
	return output
}

type TtsCredentialList struct {
	Credentials []TtsCredential `json:"credential_list"`
}

func (credList TtsCredentialList) String() string {
	output := "\n"
	for _, cred := range credList.Credentials {
		output = output + fmt.Sprintln(cred)
	}
	output = output + "\n"
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
	fmt.Println("retrieving information:")
	_, err := base.Get("./info").Receive(info, ttsError)
	if err != nil {
		fmt.Printf("error requesting information:\n %s\n", err)
		return
	}
	if is_error(ttsError) {
		fmt.Printf("error requesting information:\n %s\n", ttsError)
	} else {
		fmt.Println(info)
	}
}

func provider_list(base *sling.Sling) {
	providerList := new(TtsProviderList)
	ttsError := new(TtsError)
	fmt.Println("retrieving provider list:")
	_, err := base.Get("./oidcp").Receive(providerList, ttsError)
	if err != nil {
		fmt.Printf("error requesting list of provider:\n %s\n", err)
		return
	}
	if is_error(ttsError) {
		fmt.Printf("error requesting list of provider:\n %s\n", ttsError)
	} else {
		fmt.Println(providerList)
	}
}

func service_list(base *sling.Sling) {
	serviceList := new(TtsServiceList)
	ttsError := new(TtsError)
	fmt.Println("retrieving service list:")
	_, err := base.Get("./service").Receive(serviceList, ttsError)
	if err != nil {
		fmt.Printf("error requesting list of services:\n %s\n", err)
		return
	}
	if is_error(ttsError) {
		fmt.Printf("error requesting list of services:\n %s\n", ttsError)
	} else {
		fmt.Println(serviceList)
	}
}

func credential_list(base *sling.Sling) {
	List := new(TtsCredentialList)
	ttsError := new(TtsError)
	fmt.Println("retrieving credential list:")
	_, err := base.Get("./credential").Receive(List, ttsError)
	if err != nil {
		fmt.Printf("error requesting list of credentials:\n %s\n", err)
		return
	}
	if is_error(ttsError) {
		fmt.Printf("error requesting list of credentials:\n %s\n", ttsError)
	} else {
		fmt.Println(List)
	}
}

func credential_basic_request(serviceId string, base *sling.Sling) {
	credential := new(TtsCredentialResult)
	ttsError := new(TtsError)
	fmt.Printf("requesting credential for service [%s]:\n", serviceId)
	body := &TtsCredentialRequest{
		ServiceId: serviceId,
	}
	_, err := base.Post("./credential").BodyJSON(body).Receive(credential, ttsError)
	if err != nil {
		fmt.Printf("error requesting of credential:\n %s\n", err)
		return
	}
	if is_error(ttsError) {
		fmt.Printf("error requesting of credential:\n %s\n", ttsError)
	} else {
		fmt.Println(credential)
	}
}

func credential_revoke(credId string, base *sling.Sling) {
	fmt.Printf("revoking credential [%s]:\n", credId)
	path := fmt.Sprintf("./credential/%s", credId)
	_, err := base.Delete(path).Receive(nil, nil)
	if err != nil {
		fmt.Printf("error revoking of credential:\n %s\n", err)
		return
	} else {
		fmt.Println("credential sucessfully revoked")
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
	if !strings.HasSuffix(rawUrl, "/") {
		rawUrl = rawUrl + "/"
	}
	u, _ := url.Parse(rawUrl)
	urlBase := u.Scheme + "://" + u.Host + u.Path + apiVersion + "/"
	return urlBase
}

func main() {
	switch kingpin.MustParse(app.Parse(os.Args[1:])) {
	case ttsInfo.FullCommand():
		baseUrl := base_url(*hostUrl)
		base := base_connection(baseUrl)
		tts_info(base)
	case lsProv.FullCommand():
		baseUrl := base_url(*hostUrl)
		base := base_connection(baseUrl)
		provider_list(base)

	case lsService.FullCommand():
		baseUrl := base_url(*hostUrl)
		base := base_connection(baseUrl)
		service_list(base)

	case lsCred.FullCommand():
		baseUrl := base_url(*hostUrl)
		base := base_connection(baseUrl)
		credential_list(base)

	case basicRequest.FullCommand():
		baseUrl := base_url(*hostUrl)
		base := base_connection(baseUrl)
		credential_basic_request(*basicRequestId, base)

	case revoke.FullCommand():
		baseUrl := base_url(*hostUrl)
		base := base_connection(baseUrl)
		credential_revoke(*revokeCredId, base)
	}
}
