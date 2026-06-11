package rules

// builtinRules contains all the default normalization rules
// Order matters: structural fixes first, then renames, then defaults
var builtinRules = []Rule{
	// Structural fixes (must come first)
	ensureDisplayArray,

	// Legacy field renames
	renameLangToLocale,
	renameLangToLocaleInClaims,

	// Required field defaults
	setDisplayLocaleDefault,
	setDisplayNameFromRoot,
	setClaimDisplayLocaleDefault,

	// Cleanup empty fields
	removeEmptySVGTemplateProperties,
	removeEmptyDescription,
}

// renameLangToLocale renames "lang" to "locale" in display entries (legacy spec)
var renameLangToLocale = NewRule(
	"rename-lang-to-locale",
	"Rename 'lang' to 'locale' in display entries (legacy field name)",
	func(data map[string]interface{}) (bool, error) {
		display, ok := data["display"].([]interface{})
		if !ok {
			return false, nil
		}

		changed := false
		for _, d := range display {
			dm, ok := d.(map[string]interface{})
			if !ok {
				continue
			}
			if lang, exists := dm["lang"]; exists {
				dm["locale"] = lang
				delete(dm, "lang")
				changed = true
			}
		}
		return changed, nil
	},
)

// renameLangToLocaleInClaims renames "lang" to "locale" in claim display entries
var renameLangToLocaleInClaims = NewRule(
	"rename-lang-to-locale-in-claims",
	"Rename 'lang' to 'locale' in claim display entries (legacy field name)",
	func(data map[string]interface{}) (bool, error) {
		claims, ok := data["claims"].([]interface{})
		if !ok {
			return false, nil
		}

		changed := false
		for _, c := range claims {
			cm, ok := c.(map[string]interface{})
			if !ok {
				continue
			}
			display, ok := cm["display"].([]interface{})
			if !ok {
				continue
			}
			for _, d := range display {
				dm, ok := d.(map[string]interface{})
				if !ok {
					continue
				}
				if lang, exists := dm["lang"]; exists {
					dm["locale"] = lang
					delete(dm, "lang")
					changed = true
				}
			}
		}
		return changed, nil
	},
)

// setDisplayLocaleDefault sets locale to "en-US" if missing in display entries
var setDisplayLocaleDefault = NewRule(
	"set-display-locale-default",
	"Set display locale to 'en-US' if missing",
	func(data map[string]interface{}) (bool, error) {
		display, ok := data["display"].([]interface{})
		if !ok {
			return false, nil
		}

		changed := false
		for _, d := range display {
			dm, ok := d.(map[string]interface{})
			if !ok {
				continue
			}
			if _, exists := dm["locale"]; !exists {
				dm["locale"] = "en-US"
				changed = true
			}
		}
		return changed, nil
	},
)

// setDisplayNameFromRoot copies root "name" to display entries if missing
var setDisplayNameFromRoot = NewRule(
	"set-display-name-from-root",
	"Set display name from root 'name' field if missing",
	func(data map[string]interface{}) (bool, error) {
		rootName, ok := data["name"].(string)
		if !ok || rootName == "" {
			return false, nil
		}

		display, ok := data["display"].([]interface{})
		if !ok {
			return false, nil
		}

		changed := false
		for _, d := range display {
			dm, ok := d.(map[string]interface{})
			if !ok {
				continue
			}
			if _, exists := dm["name"]; !exists {
				dm["name"] = rootName
				changed = true
			}
		}
		return changed, nil
	},
)

// setClaimDisplayLocaleDefault sets locale to "en-US" if missing in claim display entries
var setClaimDisplayLocaleDefault = NewRule(
	"set-claim-display-locale-default",
	"Set claim display locale to 'en-US' if missing",
	func(data map[string]interface{}) (bool, error) {
		claims, ok := data["claims"].([]interface{})
		if !ok {
			return false, nil
		}

		changed := false
		for _, c := range claims {
			cm, ok := c.(map[string]interface{})
			if !ok {
				continue
			}
			display, ok := cm["display"].([]interface{})
			if !ok {
				continue
			}
			for _, d := range display {
				dm, ok := d.(map[string]interface{})
				if !ok {
					continue
				}
				if _, exists := dm["locale"]; !exists {
					dm["locale"] = "en-US"
					changed = true
				}
			}
		}
		return changed, nil
	},
)

// removeEmptySVGTemplateProperties removes empty properties objects from svg_templates
var removeEmptySVGTemplateProperties = NewRule(
	"remove-empty-svg-template-properties",
	"Remove empty 'properties' from svg_templates",
	func(data map[string]interface{}) (bool, error) {
		display, ok := data["display"].([]interface{})
		if !ok {
			return false, nil
		}

		changed := false
		for _, d := range display {
			dm, ok := d.(map[string]interface{})
			if !ok {
				continue
			}
			rendering, ok := dm["rendering"].(map[string]interface{})
			if !ok {
				continue
			}
			templates, ok := rendering["svg_templates"].([]interface{})
			if !ok {
				continue
			}
			for _, t := range templates {
				tm, ok := t.(map[string]interface{})
				if !ok {
					continue
				}
				if props, exists := tm["properties"]; exists {
					// Check if properties is empty (nil, empty map, or map with only empty values)
					if isEmpty := isEmptyProperties(props); isEmpty {
						delete(tm, "properties")
						changed = true
					}
				}
			}
		}
		return changed, nil
	},
)

// isEmptyProperties checks if a properties value is empty
func isEmptyProperties(props interface{}) bool {
	if props == nil {
		return true
	}
	pm, ok := props.(map[string]interface{})
	if !ok {
		return false
	}
	if len(pm) == 0 {
		return true
	}
	// Check if all values are empty/nil
	for _, v := range pm {
		if v != nil && v != "" {
			return false
		}
	}
	return true
}

// removeEmptyDescription removes empty description fields
var removeEmptyDescription = NewRule(
	"remove-empty-description",
	"Remove empty 'description' fields",
	func(data map[string]interface{}) (bool, error) {
		changed := false

		// Root level description
		if desc, exists := data["description"]; exists {
			if desc == nil || desc == "" {
				delete(data, "description")
				changed = true
			}
		}

		// Display level descriptions
		if display, ok := data["display"].([]interface{}); ok {
			for _, d := range display {
				dm, ok := d.(map[string]interface{})
				if !ok {
					continue
				}
				if desc, exists := dm["description"]; exists {
					if desc == nil || desc == "" {
						delete(dm, "description")
						changed = true
					}
				}
			}
		}

		// Claim level descriptions
		if claims, ok := data["claims"].([]interface{}); ok {
			for _, c := range claims {
				cm, ok := c.(map[string]interface{})
				if !ok {
					continue
				}
				if desc, exists := cm["description"]; exists {
					if desc == nil || desc == "" {
						delete(cm, "description")
						changed = true
					}
				}
			}
		}

		return changed, nil
	},
)

// ensureDisplayArray ensures display is an array (not a single object)
var ensureDisplayArray = NewRule(
	"ensure-display-array",
	"Ensure 'display' is an array, wrapping single objects",
	func(data map[string]interface{}) (bool, error) {
		display, exists := data["display"]
		if !exists {
			return false, nil
		}

		// Already an array
		if _, ok := display.([]interface{}); ok {
			return false, nil
		}

		// Single object - wrap in array
		if dm, ok := display.(map[string]interface{}); ok {
			data["display"] = []interface{}{dm}
			return true, nil
		}

		return false, nil
	},
)
