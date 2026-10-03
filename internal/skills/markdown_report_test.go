package skills

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMarkdownCannotBeBrokenOutOf(t *testing.T) {
	p := newProject(t)
	p.skill("evil", "Hello.\n")
	l := p.locked()
	p.skill("evil", "Hello.\n\nClose the fence: ```` and ``` </details> <img src=x onerror=alert(1)> | a | b | @everyone"+tagString(" hidden")+"\n")
	md := Markdown(p.check(l), "skills.lock")

	// The diff block's fence is longer than any run of backticks inside it.
	i := strings.Index(md, "diff\n")
	require.Positive(t, i)
	fence := md[strings.LastIndex(md[:i], "\n")+1 : i]
	assert.GreaterOrEqual(t, len(fence), 5)
	body := md[i+len("diff\n"):]
	end := strings.Index(body, "\n"+fence+"\n")
	require.Positive(t, end, "the block is closed by its own fence")
	assert.Contains(t, body[:end], "</details> <img src=x", "HTML stays inside the code block")
	assert.Contains(t, body[:end], "«hidden:  hidden»", "hidden text is spelled out")
	assert.NotContains(t, md, "\U000E0020")
	// Outside the block, the closing tag appears once: its own.
	assert.Equal(t, 1, strings.Count(md[:i], "<details"))
}

func TestMdCodeAndText(t *testing.T) {
	assert.Equal(t, "`a b`", mdCode("a\nb"))
	assert.Equal(t, "``a`b``", mdCode("a`b"))
	assert.Equal(t, "`` `x` ``", mdCode("`x`"))
	assert.Equal(t, "`a \\| b`", mdCode("a | b"))
	assert.Equal(t, "`«U+200B»`", mdCode("\u200b"))
	assert.Equal(t, `a \| &lt;b&gt; \*c\* &#64;team`, mdText("a | <b> *c* @team"))
}

func TestBadge(t *testing.T) {
	assert.Equal(t, "![skill: no capabilities](https://img.shields.io/badge/skill-no_capabilities-brightgreen)", Badge(Label{}))
	assert.Equal(t, "![skill: shell · file-write](https://img.shields.io/badge/skill-shell_%C2%B7_file--write-yellow)",
		Badge(Label{Capabilities: []string{"shell", "file-write"}}))
	assert.Contains(t, Badge(Label{Capabilities: []string{"secrets"}}), "-orange)")
}

func TestMarkdownWhenEverythingIsLocked(t *testing.T) {
	p := newProject(t)
	p.skill("ok", "Fine.\n")
	md := Markdown(p.check(p.locked()), "skills.lock")
	assert.Contains(t, md, "all 1 skill(s) match `skills.lock`")
	assert.NotContains(t, md, "<details")
	assert.Equal(t, "### agentgate skills: no skills found\n", Markdown(nil, "skills.lock"))
}
