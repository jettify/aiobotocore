import ast
import operator
import re
import sys
from datetime import datetime
from itertools import chain
from pathlib import Path
from typing import NamedTuple, Optional

import docutils.frontend
import docutils.nodes
import docutils.parsers.rst
import docutils.utils
import pytest
import requests
from packaging import version
from pip._internal.req import InstallRequirement
from pip._internal.req.constructors import install_req_from_line
from pip._vendor.packaging.specifiers import SpecifierSet

import aiobotocore

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

_root_path = Path(__file__).absolute().parent.parent


# date can be YYYY-MM-DD or "TBD"
_rst_ver_date_str_re = re.compile(
    r'(?P<version>\d+\.\d+\.\d+(\.dev\d+)?) \((?P<date>\d{4}-\d{2}-\d{2}|TBD)\)'
)


# from: https://stackoverflow.com/a/48719723/1241593
def _parse_rst(text: str) -> docutils.nodes.document:
    parser = docutils.parsers.rst.Parser()
    components = (docutils.parsers.rst.Parser,)
    settings = docutils.frontend.OptionParser(
        components=components
    ).get_default_values()
    document = docutils.utils.new_document('<rst-doc>', settings=settings)
    parser.parse(text, document)
    return document


def _get_assign_target_name(node: ast.Assign):
    assert len(node.targets) == 1
    target = node.targets[0]
    assert isinstance(target, ast.Name)
    return target.id


class VersionInfo(NamedTuple):
    least_version: str
    specifier_set: SpecifierSet


def _get_requirements_from_setup_py(setup_content: str):
    parsed = ast.parse(setup_content)
    top_level_vars = {"install_requires", "requires", "extras_require"}
    assignments = dict()
    for node in parsed.body:
        if isinstance(node, ast.Assign):
            target_name = _get_assign_target_name(node)
            if target_name not in top_level_vars:
                continue

            value = ast.literal_eval(node.value)
            assignments[target_name] = value

    return chain(
        assignments.get("install_requires", []),
        assignments.get("requires", []),
        assignments.get("extras_require", {}).values(),
    )


def _get_requirements_from_pyproject_toml(pyproject_content: str):
    content = tomllib.loads(pyproject_content)

    return chain(
        content["project"].get("dependencies", []),
        *content["project"].get("optional-dependencies", {}).values(),
    )


def _get_boto_module_versions(
    requirements, ensure_plus_one_patch_range: bool = False
):
    module_versions = dict()

    for ver in requirements:
        if isinstance(ver, str):
            ver: InstallRequirement = install_req_from_line(ver)
        elif isinstance(ver, list):
            assert len(ver) == 1
            ver: InstallRequirement = install_req_from_line(ver[0])
        else:
            assert False, f'Unsupported ver: {ver}'

        module = ver.req.name
        if module not in {'botocore', 'awscli', 'boto3'}:
            continue

        # NOTE: don't support complex versioning yet as requirements are unknown
        gte: Optional[version.Version] = None
        lt: Optional[version.Version] = None
        eq: Optional[version.Version] = None
        for spec in ver.req.specifier:
            if spec.operator == '>=':
                assert gte is None
                gte = version.parse(spec.version)
            elif spec.operator == '<':
                assert lt is None
                lt = version.parse(spec.version)
            elif spec.operator == '==':
                assert eq is None
                eq = version.parse(spec.version)
            else:
                assert False, f'unsupported operator: {spec.operator}'

        if ensure_plus_one_patch_range:
            assert (
                len(gte.release) == len(lt.release) == 3
            ), f'{module} gte: {gte} diff len than {lt}'
            assert lt.release == tuple(
                map(operator.add, gte.release, (0, 0, 1))
            ), f'{module} gte: {gte} not one patch off from {lt}'

        module_versions[module] = VersionInfo(
            gte.public if gte else None, ver.req.specifier
        )

    return module_versions


@pytest.mark.moto
def test_release_versions():
    # ensures versions in CHANGES.rst + __init__.py match
    init_version = version.parse(aiobotocore.__version__)

    # the init version should be in canonical from
    assert str(init_version) == aiobotocore.__version__

    changes_path = _root_path / 'CHANGES.rst'

    with changes_path.open('r') as f:
        changes_doc = _parse_rst(f.read())

    rst_ver_str = changes_doc[0][1][0][0]  # ex: 0.11.1 (2020-01-03)
    rst_prev_ver_str = changes_doc[0][2][0][0]

    rst_ver_groups = _rst_ver_date_str_re.match(rst_ver_str)
    rst_prev_ver_groups = _rst_ver_date_str_re.match(rst_prev_ver_str)

    rst_ver = version.parse(rst_ver_groups['version'])
    rst_prev_ver = version.parse(rst_prev_ver_groups['version'])

    # first the init version should match the rst version
    assert init_version == rst_ver

    # the current version must be greater than the previous version
    assert rst_ver > rst_prev_ver

    rst_date = rst_ver_groups['date']
    rst_prev_date = rst_prev_ver_groups['date']

    if rst_date == 'TBD':
        # TODO: we can now lock if we're a prerelease version
        pass
        # assert (
        #     rst_ver.is_prerelease
        # ), 'Version must be prerelease if final release date not set'
    else:
        assert (
            not rst_ver.is_prerelease
        ), 'Version must not be prerelease if release date set'

        rst_date = datetime.strptime(rst_date, '%Y-%m-%d').date()
        rst_prev_date = datetime.strptime(rst_prev_date, '%Y-%m-%d').date()

        assert (
            rst_date >= rst_prev_date
        ), 'Current release must be after last release'

    # get aioboto reqs
    with (_root_path / 'pyproject.toml').open() as f:
        content = f.read()
        aioboto_reqs = _get_boto_module_versions(
            _get_requirements_from_pyproject_toml(content),
            False,
        )

    # get awscli reqs
    awscli_resp = requests.get(
        f"https://raw.githubusercontent.com/aws/aws-cli/"
        f"{aioboto_reqs['awscli'].least_version}/setup.py"
    )
    awscli_reqs = _get_boto_module_versions(
        _get_requirements_from_setup_py(awscli_resp.text)
    )
    assert awscli_reqs['botocore'].specifier_set.contains(
        aioboto_reqs['botocore'].least_version
    )

    # get boto3 reqs
    boto3_resp = requests.get(
        f"https://raw.githubusercontent.com/boto/boto3/"
        f"{aioboto_reqs['boto3'].least_version}/setup.py"
    )
    boto3_reqs = _get_boto_module_versions(
        _get_requirements_from_setup_py(boto3_resp.text)
    )
    assert boto3_reqs['botocore'].specifier_set.contains(
        aioboto_reqs['botocore'].least_version
    )

    print()
