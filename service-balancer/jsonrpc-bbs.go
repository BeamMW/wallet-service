package main

import (
	"encoding/json"
	"fmt"
	"github.com/BeamMW/wallet-service/service-balancer/wsclient"
)

func jsonRpcProcessBbs (client *wsclient.WSClient, msg []byte) (response []byte) {
	return jsonRpcProcess(msg, func(method string, params *json.RawMessage) (errCode int, err error, result interface{}) {
		if method == "new_message" {
			counters.CountBbsMessage()
			result, err = onNewBbsMessage(client, params)
			return
		}
		counters.CountBbsBadMethod()
		err = fmt.Errorf("method '%v' not found", method)
		errCode = -32601
		return
	})
}
