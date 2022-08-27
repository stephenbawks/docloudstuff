

release-prod:
	poetry config pypi-token.pypi ${PYPI_TOKEN}
	poetry publish -n