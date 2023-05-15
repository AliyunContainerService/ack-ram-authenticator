/*
Copyright 2017 by the contributors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package server

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/AliyunContainerService/ack-ram-authenticator/pkg/config"
	"github.com/AliyunContainerService/ack-ram-authenticator/pkg/mapper/configmap"
	"github.com/AliyunContainerService/ack-ram-authenticator/pkg/mapper/crd"
	"github.com/AliyunContainerService/ack-ram-authenticator/pkg/mapper/dynamicfile"
	"github.com/AliyunContainerService/ack-ram-authenticator/pkg/mapper/file"
	"github.com/AliyunContainerService/ack-ram-authenticator/pkg/metrics"
	"github.com/AliyunContainerService/ack-ram-authenticator/pkg/utils"
	apiextcs "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/client-go/tools/clientcmd"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/AliyunContainerService/ack-ram-authenticator/pkg/mapper"
	"github.com/AliyunContainerService/ack-ram-authenticator/pkg/token"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	authenticationv1beta1 "k8s.io/api/authentication/v1beta1"
)

// tokenReviewDenyJSON is a static encoding (at init time) of the 'deny' TokenReview
var tokenReviewDenyJSON = func() []byte {
	res, err := json.Marshal(authenticationv1beta1.TokenReview{
		Status: authenticationv1beta1.TokenReviewStatus{
			Authenticated: false,
		},
	})
	if err != nil {
		logrus.WithError(err).Fatal("could not create static 'deny' JSON response")
	}
	return res
}()

// Pattern to match EC2 instance IDs
var (
	instanceIDPattern = regexp.MustCompile("^i-(\\w{8}|\\w{17})$")
)

// server state (internal)
type handler struct {
	http.ServeMux
	verifier         token.Verifier
	clusterID        string
	mappers          []mapper.Mapper
	scrubbedAccounts []string
}

// New authentication webhook server.
func New(cfg config.Config, stopCh <-chan struct{}) *Server {
	c := &Server{
		Config: cfg,
	}
	//ensure crd
	k8sconfig, err := clientcmd.BuildConfigFromFlags(cfg.Master, cfg.Kubeconfig)
	apiExtClientSet := apiextcs.NewForConfigOrDie(k8sconfig)
	err = crd.SyncCRD(apiExtClientSet)
	if err != nil {
		logrus.Fatalf("failed to sync required crd: %v", err)
	}

	mappers, err := BuildMapperChain(cfg)
	if err != nil {
		logrus.Fatalf("failed to build mapper chain: %v", err)
	}

	for _, m := range mappers {
		logrus.Infof("starting mapper %q", m.Name())
		if err := m.Start(stopCh); err != nil {
			logrus.Fatalf("start mapper %q failed", m.Name())
		}
	}

	for _, mapping := range c.RoleMappings {
		if mapping.RoleARN != "" {
			logrus.WithFields(logrus.Fields{
				"role":     mapping.RoleARN,
				"username": mapping.Username,
				"groups":   mapping.Groups,
			}).Infof("mapping IAM role")
		}
	}
	for _, mapping := range c.UserMappings {
		logrus.WithFields(logrus.Fields{
			"user":     mapping.UserARN,
			"username": mapping.Username,
			"groups":   mapping.Groups,
		}).Infof("mapping IAM user")
	}

	for _, account := range c.AutoMappedAlibabaCloudAccounts {
		logrus.WithField("accountID", account).Infof("mapping IAM Account")
	}

	cert, err := c.GetOrCreateX509KeyPair()
	if err != nil {
		logrus.WithError(err).Fatalf("could not load/generate a certificate")
	}

	if !c.KubeconfigPregenerated {
		if err := c.GenerateWebhookKubeconfig(); err != nil {
			logrus.WithError(err).Fatalf("could not create webhook kubeconfig")
		}
	}

	// start a TLS listener with our custom certs
	listener, err := tls.Listen("tcp", c.ListenAddr(), &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{*cert},
	})
	if err != nil {
		logrus.WithError(err).Fatal("could not open TLS listener")
	}

	// create a logrus logger for HTTP error logs
	errLog := logrus.WithField("http", "error").Writer()
	defer errLog.Close()

	logrus.Infof("listening on %s", listener.Addr())
	logrus.Infof("reconfigure your apiserver with `--authentication-token-webhook-config-file=%s` to enable (assuming default hostPath mounts)", c.GenerateKubeconfigPath)
	c.httpServer = http.Server{
		ErrorLog: log.New(errLog, "", 0),
		Handler:  c.getHandler(mappers),
	}
	c.listener = listener
	return c
}

// Run will run the server closing the connection if there is a struct on the channel
func (c *Server) Run(stopCh <-chan struct{}) {

	defer c.listener.Close()

	go func() {
		http.ListenAndServe(":21363", &healthzHandler{})
	}()
	if err := c.httpServer.Serve(c.listener); err != nil {
		logrus.WithError(err).Fatal("http server exited")
	}
}

type healthzHandler struct{}

func (m *healthzHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "ok")
}
func (c *Server) getHandler(mappers []mapper.Mapper) *handler {

	h := &handler{
		verifier:         token.NewVerifier(c.ClusterID),
		clusterID:        c.ClusterID,
		mappers:          mappers,
		scrubbedAccounts: c.Config.ScrubbedAliyunAccounts,
	}

	h.HandleFunc("/authenticate", h.authenticateEndpoint)
	h.Handle("/metrics", promhttp.Handler())
	h.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "ok")
	})
	return h
}

func BuildMapperChain(cfg config.Config) ([]mapper.Mapper, error) {
	modes := cfg.BackendMode
	mappers := []mapper.Mapper{}
	for _, mode := range modes {
		switch mode {
		case mapper.ModeFile:
			fallthrough
		case mapper.ModeMountedFile:
			fileMapper, err := file.NewFileMapper(cfg)
			if err != nil {
				return nil, fmt.Errorf("backend-mode %q creation failed: %v", mode, err)
			}
			mappers = append(mappers, fileMapper)
		case mapper.ModeConfigMap:
			fallthrough
		case mapper.ModeACKConfigMap:
			configMapMapper, err := configmap.NewConfigMapMapper(cfg)
			if err != nil {
				return nil, fmt.Errorf("backend-mode %q creation failed: %v", mode, err)
			}
			mappers = append(mappers, configMapMapper)
		case mapper.ModeCRD:
			crdMapper, err := crd.NewCRDMapper(cfg)
			if err != nil {
				return nil, fmt.Errorf("backend-mode %q creation failed: %v", mode, err)
			}
			mappers = append(mappers, crdMapper)
		case mapper.ModeDynamicFile:
			dynamicFileMapper, err := dynamicfile.NewDynamicFileMapper(cfg)
			if err != nil {
				return nil, fmt.Errorf("backend-mode %q creation failed: %v", mode, err)
			}
			mappers = append(mappers, dynamicFileMapper)
		default:
			return nil, fmt.Errorf("backend-mode %q is not a valid mode", mode)
		}
	}
	return mappers, nil
}

func duration(start time.Time) float64 {
	return time.Since(start).Seconds()
}

func (h *handler) isLoggableIdentity(identity *token.Identity) bool {
	for _, account := range h.scrubbedAccounts {
		if identity.AccountID == account {
			return false
		}
	}
	return true
}

func (h *handler) authenticateEndpoint(w http.ResponseWriter, req *http.Request) {
	start := time.Now()
	log := logrus.WithFields(logrus.Fields{
		"path":   req.URL.Path,
		"client": req.RemoteAddr,
		"method": req.Method,
	})

	if req.Method != http.MethodPost {
		log.Error("unexpected request method")
		http.Error(w, "expected POST", http.StatusMethodNotAllowed)
		metrics.Get().Latency.WithLabelValues(metrics.Malformed).Observe(duration(start))
		return
	}
	if req.Body == nil {
		log.Error("empty request body")
		http.Error(w, "expected a request body", http.StatusBadRequest)
		metrics.Get().Latency.WithLabelValues(metrics.Malformed).Observe(duration(start))
		return
	}
	defer req.Body.Close()

	var tokenReview authenticationv1beta1.TokenReview
	if err := json.NewDecoder(req.Body).Decode(&tokenReview); err != nil {
		log.WithError(err).Error("could not parse request body")
		http.Error(w, "expected a request body to be a TokenReview", http.StatusBadRequest)
		metrics.Get().Latency.WithLabelValues(metrics.Malformed).Observe(duration(start))
		return
	}

	// TODO: rate limit here
	// all responses from here down have JSON bodies
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	// if the token is invalid, reject with a 403
	identity, err := h.verifier.Verify(tokenReview.Spec.Token)
	if err != nil {
		if _, ok := err.(token.STSError); ok {
			metrics.Get().Latency.WithLabelValues(metrics.STSError).Observe(duration(start))
		} else {
			metrics.Get().Latency.WithLabelValues(metrics.Invalid).Observe(duration(start))
		}
		log.WithError(err).Warn("access denied")
		w.WriteHeader(http.StatusForbidden)
		w.Write(tokenReviewDenyJSON)
		return
	}

	if h.isLoggableIdentity(identity) {
		log.WithFields(logrus.Fields{
			"arn":       identity.ARN,
			"accountid": identity.AccountID,
			"userid":    identity.UserID,
			"session":   identity.SessionName,
		}).Info("STS response")

		// look up the ARN in each of our mappings to fill in the username and groups
		log = log.WithField("arn", identity.CanonicalARN)
	}

	username, groups, err := h.doMapping(identity)
	if err != nil {
		metrics.Get().Latency.WithLabelValues(metrics.Unknown).Observe(duration(start))
		log.WithError(err).Warn("access denied")
		w.WriteHeader(http.StatusForbidden)
		w.Write(tokenReviewDenyJSON)
		return
	}

	uid := fmt.Sprintf("ack-ram-authenticator:administrative:%s", username)
	if h.isLoggableIdentity(identity) {
		uid = fmt.Sprintf("ack-ram-authenticator:%s:%s", identity.AccountID, identity.UserID)
	}

	// the token is valid and the role is mapped, return success!
	log.WithFields(logrus.Fields{
		"username": username,
		"uid":      uid,
		"groups":   groups,
	}).Info("access granted")
	metrics.Get().Latency.WithLabelValues(metrics.Success).Observe(duration(start))
	w.WriteHeader(http.StatusOK)

	userExtra := map[string]authenticationv1beta1.ExtraValue{}
	if h.isLoggableIdentity(identity) {
		log.Infof("begin to config user extra info")
		userExtra["arn"] = authenticationv1beta1.ExtraValue{identity.ARN}
		userExtra["canonicalArn"] = authenticationv1beta1.ExtraValue{identity.CanonicalARN}
		userExtra["sessionName"] = authenticationv1beta1.ExtraValue{identity.SessionName}
	}

	log.Infof("userExtra is %v", userExtra)

	json.NewEncoder(w).Encode(authenticationv1beta1.TokenReview{
		Status: authenticationv1beta1.TokenReviewStatus{
			Authenticated: true,
			User: authenticationv1beta1.UserInfo{
				Username: username,
				UID:      uid,
				Groups:   groups,
				Extra:    userExtra,
			},
		},
	})
}

func (h *handler) doMapping(identity *token.Identity) (string, []string, error) {
	var errs []error

	canonicalARN := strings.ToLower(identity.CanonicalARN)

	for _, m := range h.mappers {
		mapping, err := m.Map(canonicalARN)
		if err == nil {
			// Mapping found, try to render any templates like {{ECSPrivateDNSName}}
			username, groups, err := h.renderTemplates(*mapping, identity)
			if err != nil {
				return "", nil, fmt.Errorf("mapper %s renderTemplates error: %v", m.Name(), err)
			}
			return username, groups, nil
		} else {
			if err != mapper.ErrNotMapped {
				errs = append(errs, fmt.Errorf("mapper %s Map error: %v", m.Name(), err))
			}

			if m.IsAccountAllowed(identity.AccountID) {
				return identity.CanonicalARN, []string{}, nil
			}
		}
	}

	if len(errs) > 0 {
		return "", nil, utilerrors.NewAggregate(errs)
	}
	return "", nil, mapper.ErrNotMapped
}
func (h *handler) renderTemplates(mapping config.IdentityMapping, identity *token.Identity) (string, []string, error) {
	var username string
	groups := []string{}
	var err error

	userPattern := mapping.Username
	username, err = h.renderTemplate(userPattern, identity)
	if err != nil {
		return "", nil, fmt.Errorf("error rendering username template %q: %s", userPattern, err.Error())
	}

	for _, groupPattern := range mapping.Groups {
		group, err := h.renderTemplate(groupPattern, identity)
		if err != nil {
			return "", nil, fmt.Errorf("error rendering group template %q: %s", groupPattern, err.Error())
		}
		groups = append(groups, group)
	}

	return username, groups, nil
}

func (h *handler) renderTemplate(template string, identity *token.Identity) (string, error) {
	// Private DNS requires EC2 API call
	if strings.Contains(template, "{{ECSPrivateDNSName}}") {
		if !instanceIDPattern.MatchString(identity.SessionName) {
			return "", fmt.Errorf("SessionName did not contain an instance id")
		}
		regionId := utils.GetMetaData(utils.RegionID)
		privateIp := utils.GetMetaData(utils.PrivateIPv4)
		if regionId == "" || privateIp == "" {
			return "", errors.New("not found info from metaserver when get ecs private dns name")
		}
		privateDNSName := regionId + "." + privateIp
		template = strings.Replace(template, "{{ECSPrivateDNSName}}", privateDNSName, -1)
	}

	template = strings.Replace(template, "{{AccountID}}", identity.AccountID, -1)
	sessionName := strings.Replace(identity.SessionName, "@", "-", -1)
	template = strings.Replace(template, "{{SessionName}}", sessionName, -1)
	template = strings.Replace(template, "{{SessionNameRaw}}", identity.SessionName, -1)

	return template, nil
}
