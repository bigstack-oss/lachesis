package agent

// CloseListenerForTest closes the agent's HTTP listener out from under
// the running server, forcing Serve to return a non-ErrServerClosed
// error. It exists only to exercise the server-failure exit path in
// Run; this file is compiled only by `go test`, so the method is not
// part of the production API.
func (a *Agent) CloseListenerForTest() error {
	return a.listener.Close()
}
