// Copyright 2025 The Casdoor Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package object

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/robfig/cron/v3"
)

func CleanupTokens(tokenRetentionIntervalAfterExpiry int) error {
	batchSize := 1000
	offset := 0
	currentTime := time.Now()
	deletedCount := 0

	for {
		var sessions []*Token
		session := ormer.Engine.Limit(batchSize, offset)
		err := session.Find(&sessions)
		if err != nil {
			return fmt.Errorf("failed to query tokens: %w", err)
		}

		if len(sessions) == 0 {
			break
		}

		for _, tokenRecord := range sessions {
			tokenString := tokenRecord.AccessToken
			token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
			if err != nil {
				fmt.Printf("Failed to parse token %s: %v\n", tokenRecord.Name, err)
				continue
			}

			if claims, ok := token.Claims.(jwt.MapClaims); ok {
				exp, ok := claims["exp"].(float64)
				if !ok {
					fmt.Printf("Token %s does not have an 'exp' claim\n", tokenRecord.Name)
					continue
				}
				expireTime := time.Unix(int64(exp), 0)
				tokenAfterExpiry := currentTime.Sub(expireTime).Seconds()
				if tokenAfterExpiry > float64(tokenRetentionIntervalAfterExpiry) {
					_, err = ormer.Engine.Delete(tokenRecord)
					if err != nil {
						return fmt.Errorf("failed to delete expired token %s: %w", tokenRecord.Name, err)
					}
					fmt.Printf("[%d] Deleted expired token: %s | Created: %s | Org: %s | App: %s | User: %s\n",
						deletedCount, tokenRecord.Name, tokenRecord.CreatedTime, tokenRecord.Organization, tokenRecord.Application, tokenRecord.User)
					deletedCount++
				}
			} else {
				fmt.Printf("Token %s is not valid\n", tokenRecord.Name)
			}
		}

		if len(sessions) < batchSize {
			break
		}
		offset += batchSize
	}
	return nil
}

func getTokenRetentionInterval(days int) int {
	if days <= 0 {
		days = 30
	}
	return days * 24 * 3600
}

func InitCleanupTokens() {
	schedule := "0 0 * * *"
	interval := getTokenRetentionInterval(30)

	if err := CleanupTokens(interval); err != nil {
		fmt.Printf("Error cleaning up tokens at startup: %v\n", err)
	}

	cronJob := cron.New()
	_, err := cronJob.AddFunc(schedule, func() {
		if err := CleanupTokens(interval); err != nil {
			fmt.Printf("Error cleaning up tokens: %v\n", err)
		}
	})
	if err != nil {
		fmt.Printf("Error scheduling token cleanup: %v\n", err)
		return
	}
	cronJob.Start()
}
