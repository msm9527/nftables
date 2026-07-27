// Copyright 2018 Google LLC. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package nftables

import (
	"errors"
	"testing"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// TestFromMsgTruncated verifies that decoding a message whose payload is too
// short to contain the nfgenmsg header returns an error instead of panicking.
// Monitor decodes messages on an internal goroutine, so a panic there would
// take down the whole process rather than surface as an error.
func TestFromMsgTruncated(t *testing.T) {
	decoders := []struct {
		name       string
		headerType uint16
		decode     func(netlink.Message) error
	}{
		{
			name:       "tableFromMsg",
			headerType: unix.NFT_MSG_NEWTABLE,
			decode:     func(m netlink.Message) error { _, err := tableFromMsg(m); return err },
		},
		{
			name:       "chainFromMsg",
			headerType: unix.NFT_MSG_NEWCHAIN,
			decode:     func(m netlink.Message) error { _, err := chainFromMsg(m); return err },
		},
		{
			name:       "ruleFromMsg",
			headerType: unix.NFT_MSG_NEWRULE,
			decode: func(m netlink.Message) error {
				_, err := ruleFromMsg(TableFamilyINet, m)
				return err
			},
		},
		{
			name:       "parseRuleFromMsg",
			headerType: unix.NFT_MSG_NEWRULE,
			decode:     func(m netlink.Message) error { _, err := parseRuleFromMsg(m); return err },
		},
		{
			name:       "setsFromMsg",
			headerType: unix.NFT_MSG_NEWSET,
			decode:     func(m netlink.Message) error { _, err := setsFromMsg(m); return err },
		},
		{
			name:       "elementsFromMsg",
			headerType: unix.NFT_MSG_NEWSETELEM,
			decode: func(m netlink.Message) error {
				_, err := elementsFromMsg(uint8(TableFamilyINet), m)
				return err
			},
		},
		{
			name:       "objFromMsg",
			headerType: unix.NFT_MSG_NEWOBJ,
			decode:     func(m netlink.Message) error { _, err := objFromMsg(m, false); return err },
		},
		{
			name:       "ftsFromMsg",
			headerType: unix.NFT_MSG_NEWFLOWTABLE,
			decode:     func(m netlink.Message) error { _, err := ftsFromMsg(m); return err },
		},
		{
			name:       "genFromMsg",
			headerType: unix.NFT_MSG_NEWGEN,
			decode:     func(m netlink.Message) error { _, err := genFromMsg(m); return err },
		},
		{
			name:       "handleCreateReply",
			headerType: unix.NFT_MSG_NEWRULE,
			decode:     func(m netlink.Message) error { return (&Rule{}).handleCreateReply(m) },
		},
	}

	// Every payload here is shorter than the 4-byte nfgenmsg header.
	payloads := [][]byte{nil, {}, {unix.NFPROTO_INET}, {unix.NFPROTO_INET, 0}, {unix.NFPROTO_INET, 0, 0}}

	for _, d := range decoders {
		for _, payload := range payloads {
			t.Run(d.name, func(t *testing.T) {
				msg := netlink.Message{
					Header: netlink.Header{
						Type: netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8) | netlink.HeaderType(d.headerType),
					},
					Data: payload,
				}

				err := d.decode(msg)
				if err == nil {
					t.Fatalf("decoding a %d-byte payload succeeded, want error", len(payload))
				}
				if !errors.Is(err, errTruncatedMsg) {
					t.Fatalf("got error %v, want it to wrap errTruncatedMsg", err)
				}
			})
		}
	}
}

// TestFromMsgHeaderOnly verifies that a message carrying the nfgenmsg header
// but no attributes decodes without error, so the truncation guard does not
// reject otherwise valid messages.
func TestFromMsgHeaderOnly(t *testing.T) {
	msg := netlink.Message{
		Header: netlink.Header{
			Type: netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8) | unix.NFT_MSG_NEWTABLE,
		},
		Data: []byte{unix.NFPROTO_INET, unix.NFNETLINK_V0, 0, 0},
	}

	table, err := tableFromMsg(msg)
	if err != nil {
		t.Fatalf("tableFromMsg: %v", err)
	}
	if got, want := table.Family, TableFamilyINet; got != want {
		t.Errorf("table family: got %v, want %v", got, want)
	}
}

// TestMonitorFlagsFilter guards against a bitwise precedence bug: in Go, & and
// << share precedence and associate left to right, so writing
// flags&1<<msgType evaluates as (flags&1)<<msgType and drops nearly every
// event a monitor asked for.
func TestMonitorFlagsFilter(t *testing.T) {
	for _, tt := range []struct {
		name    string
		object  MonitorObject
		action  MonitorAction
		want    []uint16
		notWant []uint16
	}{
		{
			name:    "chains",
			object:  MonitorObjectChains,
			action:  MonitorActionAny,
			want:    []uint16{unix.NFT_MSG_NEWCHAIN, unix.NFT_MSG_DELCHAIN},
			notWant: []uint16{unix.NFT_MSG_NEWTABLE, unix.NFT_MSG_NEWRULE},
		},
		{
			name:    "rules",
			object:  MonitorObjectRules,
			action:  MonitorActionAny,
			want:    []uint16{unix.NFT_MSG_NEWRULE, unix.NFT_MSG_DELRULE},
			notWant: []uint16{unix.NFT_MSG_NEWTABLE, unix.NFT_MSG_NEWCHAIN},
		},
		{
			name:    "elements",
			object:  MonitorObjectElements,
			action:  MonitorActionAny,
			want:    []uint16{unix.NFT_MSG_NEWSETELEM, unix.NFT_MSG_DELSETELEM},
			notWant: []uint16{unix.NFT_MSG_NEWSET, unix.NFT_MSG_NEWTABLE},
		},
		{
			name:    "new chains only",
			object:  MonitorObjectChains,
			action:  MonitorActionNew,
			want:    []uint16{unix.NFT_MSG_NEWCHAIN},
			notWant: []uint16{unix.NFT_MSG_DELCHAIN},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			monitor := NewMonitor(WithMonitorObject(tt.object), WithMonitorAction(tt.action))
			defer monitor.Close()

			for _, msgType := range tt.want {
				if monitor.monitorFlags&(1<<msgType) == 0 {
					t.Errorf("msgType %d filtered out, want it to pass", msgType)
				}
			}
			for _, msgType := range tt.notWant {
				if monitor.monitorFlags&(1<<msgType) != 0 {
					t.Errorf("msgType %d passed the filter, want it filtered out", msgType)
				}
			}
		})
	}
}
