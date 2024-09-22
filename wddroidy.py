"""Convert Wikidata SPARQL results into a DROID compatible signature
file.
"""

import asyncio

from src.wddroidy import wddroidy


async def main():
    """Primary entry point for this script."""
    await wddroidy.main()


if __name__ == "__main__":
    asyncio.run(main())
