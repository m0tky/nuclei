package nuclei_test

import (
	"context"
	"log"
	"os"
	"testing"
	"time"

	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestContextCancelNucleiEngine(t *testing.T) {
	// create nuclei engine with options
	ctx, cancel := context.WithCancel(context.Background())
	ne, err := nuclei.NewNucleiEngineCtx(ctx,
		nuclei.WithTemplateFilters(nuclei.TemplateFilters{Tags: []string{"oast"}}),
		nuclei.EnableStatsWithOpts(nuclei.StatsOptions{MetricServerPort: 0}),
	)
	require.NoError(t, err, "could not create nuclei engine")

	go func() {
		time.Sleep(time.Second * 2)
		cancel()
		log.Println("Test: context cancelled")
	}()

	// load targets and optionally probe non http/https targets
	ne.LoadTargets([]string{"http://honey.scanme.sh"}, false)
	// when callback is nil it nuclei will print JSON output to stdout
	err = ne.ExecuteWithCallback(nil)
	if err != nil {
		// we expect a context cancellation error
		require.ErrorIs(t, err, context.Canceled, "was expecting context cancellation error")
	}
	defer ne.Close()
}

func TestHeadlessOptionInitialization(t *testing.T) {
	ne, err := nuclei.NewNucleiEngineCtx(
		context.Background(),
		nuclei.EnableHeadlessWithOpts(&nuclei.HeadlessOpts{
			PageTimeout:     20,
			ShowBrowser:     false,
			UseChrome:       false,
			HeadlessOptions: []string{},
		}),
	)

	require.NoError(t, err, "could not create nuclei engine with headless options")
	require.NotNil(t, ne, "nuclei engine should not be nil")

	// Verify logger is initialized
	require.NotNil(t, ne.Logger, "logger should be initialized")

	defer ne.Close()
}

func TestThreadSafeNucleiEngineWithNoHostErrors(t *testing.T) {
	tempTemplate, err := os.CreateTemp(t.TempDir(), "thread-safe-no-host-errors.*.yaml")
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = os.Remove(tempTemplate.Name())
	})

	_, err = tempTemplate.WriteString(`id: thread-safe-no-host-errors
info:
  name: Thread Safe (NoHostErrors)
  author: nuclei-sdk-test
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: word
        words:
          - "ok"`)
	require.NoError(t, err)
	require.NoError(t, tempTemplate.Close())

	options := types.DefaultOptions().Copy()
	options.NoHostErrors = true
	options.Timeout = 2
	options.Retries = 0
	options.BulkSize = 1
	options.TemplateThreads = 1
	options.Templates = append(options.Templates, tempTemplate.Name())

	ne, err := nuclei.NewThreadSafeNucleiEngineCtx(context.TODO(), nuclei.WithOptions(options))
	if err != nil {
		require.NoError(t, err, "could not create nuclei engine")
	}

	defer ne.Close()

	if err := ne.GlobalLoadAllTemplates(); err != nil {
		require.NoError(t, err, "could not load templates")
	}

	// ne.GlobalResultCallback(func(event *output.ResultEvent) {
	// 	fmt.Println(event.Host, event.Info.SeverityHolder.Severity)
	// })

	if err := ne.ExecuteNucleiWithOptsCtx(context.TODO(), []string{"scanme.sh"}); err != nil {
		require.NoError(t, err, "nuclei execution should not return an error")
	}
}
