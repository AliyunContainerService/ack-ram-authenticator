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

package main

import (
	"fmt"
	"github.com/AliyunContainerService/ack-ram-authenticator/pkg/token"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"os"
)

var tokenCmd = &cobra.Command{
	Use:   "token",
	Short: "Authenticate using ACK RAM and get token for Kubernetes",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		region := viper.GetString("region")
		roleARN := viper.GetString("role")
		clusterID := viper.GetString("clusterID")
		tokenOnly := viper.GetBool("tokenOnly")

		if clusterID == "" {
			fmt.Fprintf(os.Stderr, "Error: cluster ID not specified\n")
			cmd.Usage()
			os.Exit(1)
		}

		var tok token.Token
		var out string
		var err error
		gen, err := token.NewGenerator()
		if err != nil {
			fmt.Fprintf(os.Stderr, "could not get token: %v\n", err)
			os.Exit(1)
		}
		//if roleARN != "" {
		//	// if a role was provided, assume that role for the token
		//	tok, err = gen.GetWithRole(clusterID, roleARN)
		//} else {
		//	// otherwise sign the token with immediately available credentials
		//	tok, err = gen.Get(clusterID)
		//}
		tok, err = gen.GetWithOptions(&token.GetTokenOptions{
			ClusterID:     clusterID,
			AssumeRoleARN: roleARN,
			Region:        region,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "could not get token: %v\n", err)
			os.Exit(1)
		}
		if tokenOnly {
			out = tok.Token
		} else {
			out = gen.FormatJSON(tok)
		}
		fmt.Println(out)
	},
}

func init() {
	rootCmd.AddCommand(tokenCmd)
	tokenCmd.Flags().String("region", "", "AlibabaCloud region to use for assume role calls")
	tokenCmd.Flags().StringP("role", "r", "", "Assume an RAM Role ARN before signing this token")
	tokenCmd.Flags().Bool("token-only", false, "Return only the token for use with Bearer token based tools")
	tokenCmd.Flags().Bool("cache", false, "Cache the credential on disk until it expires. Uses the aws profile specified by AWS_PROFILE or the default profile.")
	viper.BindPFlag("region", tokenCmd.Flags().Lookup("region"))
	viper.BindPFlag("role", tokenCmd.Flags().Lookup("role"))
	viper.BindPFlag("tokenOnly", tokenCmd.Flags().Lookup("token-only"))
	viper.BindPFlag("cache", tokenCmd.Flags().Lookup("cache"))
	viper.BindEnv("role", "DEFAULT_ROLE")
}
