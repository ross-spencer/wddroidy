# Get help
help:
  just -l

## Package repository as tar for easy distribution
tar-source: package-deps
	rm -rf tar-src/
	mkdir tar-src/
	git-archive-all --prefix template/ tar-src/template-v0.0.0.tar.gz

## Upgrade dependencies for packaging
package-deps:
	python3 -m pip install -U twine wheel build git-archive-all

## Package the source code
package-source: package-deps clean
	python -m build .

## Check the distribution is valid
package-check: clean package-source
	twine check dist/*

## Upload package to test.pypi
package-upload-test: clean package-deps package-check
	twine upload dist/* --repository-url https://test.pypi.org/legacy/ --verbose

## Upload package to pypi
package-upload: clean package-deps package-check
	twine upload dist/* --repository-url https://upload.pypi.org/legacy/ --verbose

## Run pre-commit-checks.
pre-commit-checks:
	pre-commit run --all-files

## Upgrade project dependencies
upgrade:
	pip-upgrade

## Generate documentation
docs:
	pdoc3 --force --html -o docs src/
	mv docs/src/* docs/.
	rm -r docs/src

## Serve the documentation
serve-docs:
	python3 -m http.server --directory docs/

## Clean the package directory
clean:
	rm -rf src/*.egg-info/
	rm -rf build/
	rm -rf dist/
	rm -rf tar-src/
