/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/google/tink/go/kwp/subtle"
	"github.com/spf13/cobra"

	"go.step.sm/crypto/pemutil"

	"github.com/smallstep/pem-key-wrap/internal/termutil"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:                   "pem-key-wrap [--out <file>] <private-key> <wrapping-key>",
	DisableFlagsInUseLine: true,
	SilenceUsage:          true,
	Short:                 "pem-key-wrap wraps a key using RSAES-OAEP with SHA-256 + AES-KWP",
	Example:               `  pem-key-wrap --out wrapped.key priv.key wrapping.key`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if l := len(args); l != 2 {
			return showErrUsage(cmd)
		}

		out, err := cmd.Flags().GetString("out")
		if err != nil {
			return showErrUsage(cmd)
		}

		privateKeyName := args[0]
		wrappingKeyName := args[1]

		priv, err := pemutil.Read(privateKeyName)
		if err != nil {
			return fmt.Errorf("failed to read %q: %w", privateKeyName, err)
		}

		privData, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return fmt.Errorf("failed to marshal private key: %w", err)
		}

		pub, err := pemutil.Read(wrappingKeyName)
		if err != nil {
			return fmt.Errorf("failed to read %q: %w", wrappingKeyName, err)
		}

		wrappingKey, ok := pub.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("failed to wrap key: public key must be an RSA key")
		}

		aesKey := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, aesKey); err != nil {
			return fmt.Errorf("failed to create AES key: %w", err)
		}

		kwp, err := subtle.NewKWP(aesKey)
		if err != nil {
			return fmt.Errorf("failed to create key wrapper: %w", err)
		}

		wrappedData, err := kwp.Wrap(privData)
		if err != nil {
			return fmt.Errorf("failed to wrap private key: %w", err)
		}

		aesKeyEnc, err := rsa.EncryptOAEP(crypto.SHA256.New(), rand.Reader, wrappingKey, aesKey, nil)
		if err != nil {
			return fmt.Errorf("failed to encrypt AES key: %w", err)
		}

		output := append(aesKeyEnc, wrappedData...)

		if out != "" {
			if err := os.WriteFile(out, output, 0600); err != nil {
				return fmt.Errorf("failed to write to %q: %w", out, err)
			}
		} else {
			if _, err := os.Stdout.Write(output); err != nil {
				return fmt.Errorf("failed to write to stdout: %w", err)
			}
		}

		return nil
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

var errUsage = errors.New("usage")

func showErrUsage(cmd *cobra.Command) error {
	cmd.SilenceErrors = true
	cmd.SilenceUsage = false
	return errUsage
}

func init() {
	// Define a password reader
	pemutil.PromptPassword = func(s string) ([]byte, error) {
		if s[len(s)-1] != ':' {
			s += ":"
		}
		return termutil.ReadPassword(s)
	}

	rootCmd.Flags().String("out", "", "The output file to use.")
}
