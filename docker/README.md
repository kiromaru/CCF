# Docker images for CCF

- `app_run`: Builds the image containing all runtime dependencies for CCF, as well as the latest release of CCF (as per https://github.com/microsoft/CCF/releases/latest). To be used by CCF operators.
- `app_ci`: Builds the image containing all build dependencies for CCF applications. To be used by CCF application developers.
- `ccf_ci`: Builds the image containing all build dependencies for CCF itself. To be used by CCF contributors. It is also used by CCF Continuous Integration pipeline.

To build a given image, run:

```bash
$ cd CCF/
$ docker build -t <tag> -f docker/<app_run|app_ci|ccf_ci> .
```
