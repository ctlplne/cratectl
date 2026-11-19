// SPDX-License-Identifier: BUSL-1.1
package debian

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

const MaxControlBytes = 256 << 10

var ErrControl = errors.New("invalid Debian binary package control stanza")

var (
	packageName        = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]{1,127}$`)
	architecture       = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
	fieldName          = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,63}$`)
	upstreamVersion    = regexp.MustCompile(`^[0-9][0-9A-Za-z.+~:-]*$`)
	debianRevision     = regexp.MustCompile(`^[0-9A-Za-z+.~]+$`)
	debianVersionEpoch = regexp.MustCompile(`^[0-9]+$`)
)

type Control struct {
	Package, Version, Architecture string
	Stanza                         string
}

func (c Control) PoolPath() string {
	return "pool/" + c.Package + "/" + c.Version + "/" + c.Architecture + "/" + c.Package + ".deb"
}

func ValidPoolPath(path string) bool {
	parts := strings.Split(path, "/")
	return len(parts) == 5 && parts[0] == "pool" && packageName.MatchString(parts[1]) && ValidVersion(parts[2]) &&
		architecture.MatchString(parts[3]) && parts[4] == parts[1]+".deb"
}

func ValidVersion(version string) bool {
	if len(version) > 256 {
		return false
	}
	if epoch, rest, ok := strings.Cut(version, ":"); ok {
		if !debianVersionEpoch.MatchString(epoch) {
			return false
		}
		if _, err := strconv.ParseUint(epoch, 10, 31); err != nil {
			return false
		}
		version = rest
	}
	if at := strings.LastIndexByte(version, '-'); at >= 0 {
		if !debianRevision.MatchString(version[at+1:]) {
			return false
		}
		version = version[:at]
	}
	return upstreamVersion.MatchString(version)
}

// ParseControl validates one deb822 binary control stanza. Keep its dependency
// fields and continuation lines intact so a stock solver reads the same data.
func ParseControl(raw []byte) (Control, error) {
	var c Control
	if len(raw) == 0 || len(raw) > MaxControlBytes || !utf8.Valid(raw) {
		return c, ErrControl
	}
	for _, b := range raw {
		if b < ' ' && b != '\t' && b != '\n' || b == 0x7f {
			return c, ErrControl
		}
	}
	stanza := strings.TrimRight(string(raw), "\n")
	fields := make(map[string]string)
	last := ""
	for line := range strings.SplitSeq(stanza, "\n") {
		if line == "" || len(line) > 16<<10 {
			return c, ErrControl
		}
		if line[0] == ' ' || line[0] == '\t' {
			if last == "" || last == "package" || last == "version" || last == "architecture" || last == "maintainer" {
				return c, ErrControl
			}
			continue
		}
		name, field, ok := strings.Cut(line, ":")
		if !ok || !fieldName.MatchString(name) || len(fields) >= 128 {
			return c, ErrControl
		}
		last = strings.ToLower(name)
		if _, found := fields[last]; found {
			return c, ErrControl
		}
		switch last {
		case "filename", "size", "md5sum", "sha1", "sha256", "sha512":
			return c, ErrControl
		}
		fields[last] = strings.Trim(field, " \t")
	}
	if !packageName.MatchString(fields["package"]) || !ValidVersion(fields["version"]) || !architecture.MatchString(fields["architecture"]) ||
		fields["maintainer"] == "" || fields["description"] == "" {
		return c, ErrControl
	}
	c = Control{Package: fields["package"], Version: fields["version"], Architecture: fields["architecture"], Stanza: stanza + "\n"}
	return c, nil
}
