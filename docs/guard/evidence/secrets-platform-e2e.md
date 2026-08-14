# HOL Guard Secrets platform validation

This marker binds the protected pull-request checks to the final hardening tree after temporary validation workflows have removed themselves.

The release gate requires the permanent Linux, macOS, and Windows exact-wheel matrix, the repository CI and security workflows, review resolution, and the installed-wheel Git and pre-commit smoke test to pass on this head before merge.
