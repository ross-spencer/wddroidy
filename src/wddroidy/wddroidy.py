"""Create a signature file for DROID using Wikidata.

# pylint: disable=E501
# ruff: noqa: E501

Simplified DROID signature file example:

```
    <?xml version="1.0"?>
    <FFSignatureFile xmlns="http://www.nationalarchives.gov.uk/pronom/SignatureFile" Version="1" DateCreated="2024-09-18T12:46:55+00:00">
    <InternalSignatureCollection>
        <InternalSignature ID="3" Specificity="Specific">
            <ByteSequence Reference="BOFoffset" Sequence="04??[01:0C][01:1F]{28}([41:5A]|[61:7A]){10}(43|44|46|4C|4E)" Offset="0" />
        </InternalSignature>
    </InternalSignatureCollection>
    <FileFormatCollection>
        <FileFormat ID="1" Name="Development Signature" PUID="dev/1" Version="1.0" MIMEType="application/octet-stream">
        <InternalSignatureID>1</InternalSignatureID>
        <Extension>ext</Extension>
        </FileFormat>
    </FileFormatCollection>
    </FFSignatureFile>
```

"""

import argparse
import asyncio
import datetime
import json
import logging
import os
import re
import time
import xml.dom.minidom
from datetime import timezone
from importlib.metadata import version
from typing import Final
from xml.dom.minidom import parseString

from SPARQLWrapper import JSON, SPARQLWrapper

# Set up logging.
logging.basicConfig(
    format="%(asctime)-15s %(levelname)s :: %(filename)s:%(lineno)s:%(funcName)s() :: %(message)s",  # noqa: E501
    datefmt="%Y-%m-%d %H:%M:%S",
    level="INFO",
    handlers=[
        logging.StreamHandler(),
    ],
)

# Format logs using UTC time.
logging.Formatter.converter = time.gmtime


logger = logging.getLogger(__name__)

default_endpoint_url: Final[str] = "https://query.wikidata.org/sparql"

default_query: Final[
    str
] = """SELECT DISTINCT ?uri ?uriLabel ?puid ?extension ?mimetype ?encoding ?referenceLabel ?date ?relativity ?offset ?sig WHERE {
  { ?uri (wdt:P31/(wdt:P279*)) wd:Q235557. }
  UNION
  { ?uri (wdt:P31/(wdt:P279*)) wd:Q26085352. }
  FILTER(EXISTS { ?uri (wdt:P2748|wdt:P1195|wdt:P1163|ps:P4152) _:b2. })
  FILTER((STRLEN(?sig)) >= 8 )
  OPTIONAL { ?uri wdt:P2748 ?puid. }
  OPTIONAL { ?uri wdt:P1195 ?extension. }
  OPTIONAL { ?uri wdt:P1163 ?mimetype. }
  OPTIONAL {
    ?uri p:P4152 ?object.
    OPTIONAL { ?object pq:P3294 ?encoding. }
    OPTIONAL { ?object ps:P4152 ?sig. }
    OPTIONAL { ?object pq:P2210 ?relativity. }
    OPTIONAL { ?object pq:P4153 ?offset. }
    OPTIONAL {
      ?object prov:wasDerivedFrom ?provenance.
      OPTIONAL {
        ?provenance pr:P248 ?reference;
          pr:P813 ?date.
      }
    }
  }
  SERVICE wikibase:label { bd:serviceParam wikibase:language "[AUTO_LANGUAGE], <<lang>>". }
}
ORDER BY (?uri)
"""

PRONOM_REGEX_ALLOWED: Final[str] = r"^[a-fA-F0-9\*\[\]{}:-]+$"
UTC_TIME_FORMAT: Final[str] = "%Y-%m-%dT%H:%M:%SZ"
BOF_OFFSET: Final[str] = "BOFoffset"
EOF_OFFSET: Final[str] = "EOFoffset"


def new_prettify(c):
    """Remove excess newlines from DOM output.

    via: https://stackoverflow.com/a/14493981
    """
    reparsed = parseString(c)
    return "\n".join(
        [
            line
            for line in reparsed.toprettyxml(indent=" " * 2).split("\n")
            if line.strip()
        ]
    )


def get_utc_timestamp_now():
    """Get a formatted UTC timestamp for 'now' that can be used when
    a timestamp is needed.
    """
    return datetime.datetime.now(timezone.utc).strftime(UTC_TIME_FORMAT)


def get_version():
    """Get script version."""
    try:
        return version("wddroidy")
    except Exception:  # pylint: disable=W0718
        return "0.0.0-dev"


def get_results(endpoint_url, query):
    """Retrieve results from the Wikidata Query Service.

    See: https://w.wiki/CX6 for more information about the user-agent
    policies of Wikidata.
    """
    user_agent = f"digipres-wddroidy/{get_version()}"
    sparql = SPARQLWrapper(endpoint_url, agent=user_agent)
    sparql.setQuery(query)
    sparql.setReturnFormat(JSON)
    return sparql.query().convert()


def create_many_to_one_byte_sequence(signature_counter: int, item: list):
    """Create a many to one byte sequence, i.e. a format with multiple
    Internal Signatures.
    """
    internal_signature = ""
    ids = []
    for value in item:
        internal_signature = f"""
            {internal_signature.strip()}<InternalSignature ID="{signature_counter}" Specificity="Specific">
            <ByteSequence Reference='{value[1]}' Sequence='{value[0]}' Offset="{value[2]}"/>
            </InternalSignature>
        """
        ids.append(signature_counter)
        signature_counter += 1
    return internal_signature.strip(), signature_counter, ids


def create_one_to_many_byte_sequence(item: list):
    """Create a byte sequence object."""
    byte_sequence = ""
    for value in item:
        byte_sequence = f"""
            {byte_sequence.strip()}<ByteSequence Reference=\"{value[1]}\" Sequence=\"{value[0]}\" Offset=\"{value[2]}\"/>
        """
    return byte_sequence


async def create_internal_sig_collection(signature_counter: int, item: list):
    """Create the InternalSignatureCollection object.

    ```xml
        <InternalSignature ID="3" Specificity="Specific">
            <ByteSequence Reference="BOFoffset" Sequence="04??[01:0C][01:1F]{28}([41:5A]|[61:7A]){10}(43|44|46|4C|4E)"/>
        </InternalSignature>
    ```
    """
    if not item:
        return "", [], signature_counter
    rels = []
    id_list = []
    bs = ""
    internal_signature = ""
    for value in item:
        rels.append(value[1])
    bof = rels.count(BOF_OFFSET)
    eof = rels.count(EOF_OFFSET)
    if len(item) == 1 or (bof == 1 and eof == 1):
        bs = create_one_to_many_byte_sequence(item)
        internal_signature = f"""
            <InternalSignature ID=\"{signature_counter}\" Specificity=\"Specific\">
            {bs}</InternalSignature>
        """
        id_list.append(signature_counter)
        signature_counter += 1
    elif bof > 1:
        internal_signature, signature_counter, id_list = (
            create_many_to_one_byte_sequence(signature_counter, item)
        )
    return internal_signature.strip(), id_list, signature_counter


async def get_qid(item: dict):
    """Get a QID from its URI/IRI."""
    uri = item["uri"]["value"]
    return uri.rsplit("entity/")[1]


async def create_file_format_collection(idx: int, item: dict, id_list: dict, ext: list):
    """Create the FileFormatCollection object.

    ```
        <FileFormat ID="1" Name="Development Signature" PUID="dev/1" Version="1.0" MIMEType="application/octet-stream">
            <InternalSignatureID>1</InternalSignatureID>
            <Extension>ext</Extension>
        </FileFormat>
    ```

    Requires:

        ?uri
        ?uriLabel
        ?mimetype

    """

    uri = None
    name = None
    mime = None

    try:
        uri = item["uri"]["value"]
    except KeyError:
        pass
    try:
        name = item["uriLabel"]["value"]
    except KeyError:
        pass
    try:
        mime = item["mimetype"]["value"]
    except KeyError:
        pass

    qid = uri.rsplit("entity/")[1]

    for char in (">", "'", '"', "<", "/", "\\", "&"):
        if char not in name:
            continue
        name = name.replace(char, "#")

    internal_sigs = ""
    for id_ in id_list:
        internal_sigs = (
            f"{internal_sigs.strip()}<InternalSignatureID>{id_}</InternalSignatureID>"
        )

    ff = f"""
        <FileFormat ID=\"{idx}\" Name=\"{name}\" PUID=\"{qid}\" Version="" MIMEType=\"{mime}\">
           {internal_sigs}
           {ext}
        </FileFormat>
    """
    return ff.strip(), qid


async def extract_external(qid: list):
    """Extract external signatures from the data."""
    exts = []
    for item in qid:
        try:
            exts.append(item["extension"]["value"])
        except KeyError:
            continue
    exts = list(set(exts))
    external_signatures = ""
    if not exts:
        return ""
    for item in exts:
        external_signature = f"{external_signatures}<Extension>{item}</Extension>"
    return external_signature.strip()


def pre_process_signature(item: dict) -> str:
    """Pre-process a signature to remove some low-hanging compatibility
    issues, e.g. trim spaces, and make upper-case.
    """
    return item["sig"]["value"].strip().upper().replace(" ", "")


async def extract_sigs(qid: list):
    """Extract signatures from the given dict."""
    sig_data = []
    entity = None
    for item in qid:
        if not entity:
            entity = item["uri"]["value"]
        sig = pre_process_signature(item)
        valid_sig = re.fullmatch(PRONOM_REGEX_ALLOWED, sig)
        if not valid_sig:
            logger.info("rejecting sig data for: %s", entity)
            continue
        rel = item.get("relativity", {}).get("value", None)
        if not rel:
            continue
        if rel.endswith("Q35436009"):
            rel = BOF_OFFSET
        elif rel.endswith("Q1148480"):
            rel = EOF_OFFSET
        off = item.get("offset", {}).get("value", 0)
        data = (sig, rel, off)
        if data not in sig_data:
            sig_data.append(data)
    sig_data = list(set(sig_data))
    if len(sig_data) > 1:
        # Need to check the signature makes sense, and if not, eject
        # the set.
        rels = []
        for item in sig_data:
            rels.append(item[1])
        bof = rels.count(BOF_OFFSET)
        eof = rels.count(EOF_OFFSET)
        if bof > 2 and eof >= 1:
            logging.info("rejecting sig data for: %s", entity)
            return []
    return sig_data


async def process_results(results: dict, filename: str):
    """Process results into a DROID signature file."""

    # pylint: disable=R0914

    isc = ""
    ffc = ""
    list_qids = []
    signature_counter = 1
    res = results["results"]["bindings"]
    idx = 0
    for item in res:
        qid = await get_qid(item)
        if qid in list_qids:
            continue
        if qid not in list_qids:
            idx += 1
            list_qids.append(qid)
        qid_data = [val for val in res if val["uri"]["value"].endswith(qid)]
        sigs = await extract_sigs(qid_data)
        ext = await extract_external(qid_data)
        isc_, id_list, signature_counter = await create_internal_sig_collection(
            signature_counter, sigs
        )
        isc = f"{isc}{isc_}"
        qid_ffc, qid = await create_file_format_collection(idx, item, id_list, ext)
        ffc = f"{ffc.strip()}{qid_ffc.strip()}"
    droid_template = f"""
        <?xml version='1.0'?>
        <FFSignatureFile xmlns='http://www.nationalarchives.gov.uk/pronom/SignatureFile' Version='1' DateCreated='{get_utc_timestamp_now()}'>
        <InternalSignatureCollection>{isc}</InternalSignatureCollection>
        <FileFormatCollection>{ffc}</FileFormatCollection></FFSignatureFile>
    """
    dom = xml.dom.minidom.parseString(droid_template.strip().replace("\n", ""))
    pretty_xml = dom.toprettyxml(indent=" ")
    prettier_xml = new_prettify(pretty_xml)
    logger.info("outputting to: %s", filename)
    logger.info("file formats listed: %s", idx)
    logger.info("internal signatures output: %s", signature_counter)
    with open(filename, "w", encoding="utf=8") as output_file:
        output_file.write(prettier_xml)


async def main():
    """Primary entry point for this script."""

    parser = argparse.ArgumentParser(
        prog="wddroidy",
        description="create a DROID compatible signature file from Wikidata",
        epilog="for more information visit https://github.com/ross-spencer/wddroidy",
    )
    parser.add_argument(
        "--definitions",
        help="use a local definitions file, e.g. from Siegfried",
        required=False,
        default=os.path.join("definitions", "wikidata-definitions-3.0.0"),
    )
    parser.add_argument(
        "--wdqs",
        "-w",
        help="live results from Wikidata",
        required=False,
        action="store_true",
    )
    parser.add_argument(
        "--lang",
        "-l",
        help="change Wikidata language results",
        required=False,
        default="en",
    )
    parser.add_argument(
        "--limit",
        "-n",
        help="limit the number of resukts",
        required=False,
        default="",
    )
    parser.add_argument(
        "--output",
        "-o",
        help="filename to output to",
        default="DROID_SignatureFile_WDQS.xml",
    )
    parser.add_argument(
        "--output-date",
        "-t",
        help="output a default file with the current timestamp",
        action="store_true",
    )
    parser.add_argument(
        "--endpoint",
        "-url",
        help="url of the WDQS",
        default=default_endpoint_url,
    )
    args = parser.parse_args()
    data = {}
    if args.definitions and not args.wdqs:
        logger.info("using stored definitions file")
        data = None
        with open(args.definitions, encoding="utf-8") as definitions:
            data = json.loads(definitions.read())

    if args.wdqs:
        logger.info("connecting to WDQS")
        query = default_query.replace("<<lang>>", args.lang, 1)
        if args.limit:
            query = f"{query}LIMIT {args.limit}"
        data = get_results(args.endpoint, query)

    filename = args.output
    if args.output_date:
        filename = (
            f"DROID_SignatureFile_WDQS_{get_utc_timestamp_now().replace(':', '-')}.xml"
        )
    await process_results(results=data, filename=filename)


if __name__ == "__main__":
    asyncio.run(main())
