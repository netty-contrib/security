# Filter
A filter provides functions for traffic decision.
It consists of functions for validating a new channels
and individual payloads.

### New Channel Validation
When a new channel is created at `ChannelHandler#channelActive` then
`Filter#validateChannelActive` should be called. The filter
implementation will then return appropriate `Action` to be taken
for the new Channel.

### Individual Payload Validation
When a new payload is received at `ChannelHandler#channelRead` then
`Filter#validateObject` should be called. The filter will then return
appropriate `Action` to be taken for the payload.
