#!/usr/bin/env python3

"""matrix-archive

Archive Matrix room messages. Creates a YAML log of all room
messages, including media.

Use the unattended batch mode to fetch everything in one go without
having to type anything during script execution. You can set all
the necessary values with arguments to your command call.

If you don't want to put your passwords in the command call, you
can still set the default values for homeserver, user ID and room
keys path already to have them suggested to you during interactive
execution. Rooms that you specify in the command call will be
automatically fetched before prompting for further input.

Example calls:

./matrix-archive.py
    Run program in interactive mode.

./matrix-archive.py backups
    Set output path for fetched data.

./matrix-archive.py --batch --user '@user:matrix.org' --userpass secret --keys element-keys.txt --keyspass secret
    Use unattended batch mode to login.

./matrix-archive.py --room '!Abcdefghijklmnopqr:matrix.org'
    Automatically fetch a room.

./matrix-archive.py --room '!Abcdefghijklmnopqr:matrix.org' --room '!Bcdefghijklmnopqrs:matrix.org'
    Automatically fetch two rooms.

./matrix-archive.py --roomregex '.*:matrix.org'
    Automatically fetch all rooms which match a regex pattern.

"""


from nio import (
    AsyncClient,
    AsyncClientConfig,
    MatrixRoom,
    MessageDirection,
    RedactedEvent,
    RoomEncryptedMedia,
    RoomMessage,
    RoomMessageFormatted,
    RoomMessageMedia,
    crypto,
    store,
    exceptions
)
from functools import partial
from typing import Union, TextIO
from urllib.parse import urlparse
import aiofiles
import argparse
import asyncio
import getpass
import os
import re
import sys
import yaml


DEVICE_NAME = "matrix-archive"


def parse_args():
    """Parse arguments from command line call"""

    parser = argparse.ArgumentParser(
        description=__doc__,
        add_help=False,  # Use individual setting below instead
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "folder",
        metavar="FOLDER",
        default=".",
        nargs="?",  # Make positional argument optional
        help="""Set output folder
             """,
    )
    parser.add_argument(
        "--help",
        action="help",
        help="""Show this help message and exit
             """,
    )
    parser.add_argument(
        "--batch",
        action="store_true",
        help="""Use unattended batch mode
             """,
    )
    parser.add_argument(
        "--server",
        metavar="HOST",
        default="https://matrix-client.matrix.org",
        help="""Set default Matrix homeserver
             """,
    )
    parser.add_argument(
        "--user",
        metavar="USER_ID",
        default="@user:matrix.org",
        help="""Set default user ID
             """,
    )
    parser.add_argument(
        "--userpass",
        metavar="PASSWORD",
        help="""Set default user password
             """,
    )
    parser.add_argument(
        "--keys",
        metavar="FILENAME",
        default="element-keys.txt",
        help="""Set default path to room E2E keys
             """,
    )
    parser.add_argument(
        "--keyspass",
        metavar="PASSWORD",
        help="""Set default passphrase for room E2E keys
             """,
    )
    parser.add_argument(
        "--room",
        metavar="ROOM_ID",
        default=[],
        action="append",
        help="""Add room to list of automatically fetched rooms
             """,
    )
    parser.add_argument(
        "--roomregex",
        metavar="PATTERN",
        default=[],
        action="append",
        help="""Same as --room but by regex pattern
             """,
    )

    return parser.parse_args()


def mkdir(path):
    try:
        os.mkdir(path)
    except FileExistsError:
        pass
    return path


async def create_client() -> AsyncClient:
    homeserver = ARGS.server
    user_id = ARGS.user
    password = ARGS.userpass
    if not ARGS.batch:
        homeserver = input(f"Enter URL of your homeserver: [{homeserver}] ") or homeserver
        user_id = input(f"Enter your full user ID: [{user_id}] ") or user_id
        password = getpass.getpass()
    client = AsyncClient(
        homeserver=homeserver,
        user=user_id,
        config=AsyncClientConfig(store=store.SqliteMemoryStore),
    )
    await client.login(password, DEVICE_NAME)
    client.load_store()
    room_keys_path = ARGS.keys
    room_keys_password = ARGS.keyspass
    if not ARGS.batch:
        room_keys_path = input(f"Enter full path to room E2E keys: [{room_keys_path}] ") or room_keys_path
        room_keys_password = getpass.getpass("Room keys password: ")
    print("Importing keys. This may take a while...")
    await client.import_keys(room_keys_path, room_keys_password)
    return client


async def select_room(client: AsyncClient, selected_rooms: set) -> MatrixRoom:
    for room_id in client.rooms:
        if room_id in selected_rooms:
            # Has already been selected before
            continue
        if room_id in ARGS.room or any(re.match(pattern, room_id) for pattern in ARGS.roomregex):
            print(f"Selected room: {room_id}")
            selected_rooms.add(room_id)
            return client.rooms[room_id]
    if ARGS.batch:
        # Unattended batch mode finished. Exit program
        raise KeyboardInterrupt
    print("\nList of joined rooms (room id, display name):")
    for room_id, room in client.rooms.items():
        print(f"{room_id}, {room.display_name}")
    room_id = input(f"Enter room id: ")
    return client.rooms[room_id]


async def write_event(
    client: AsyncClient, room: MatrixRoom, output_file: TextIO, event: RoomMessage
) -> None:
    media_dir = mkdir(f"{OUTPUT_DIR}/{room.display_name}_{room.room_id}_media")
    serialize_event = lambda event_payload: yaml.dump(
        [
            {
                **dict(
                    sender_id=event.sender,
                    sender_name=room.users[event.sender].display_name,
                    timestamp=event.server_timestamp,
                ),
                **event_payload,
            }
        ]
    )

    if isinstance(event, RoomMessageFormatted):
        await output_file.write(serialize_event(dict(type="text", body=event.body,)))
    elif isinstance(event, (RoomMessageMedia, RoomEncryptedMedia)):
        media_data = await download_mxc(client, event.url)
        filename = f"{media_dir}/{event.body}"
        async with aiofiles.open(filename, "wb") as f:
            await f.write(
                crypto.attachments.decrypt_attachment(
                    media_data,
                    event.source["content"]["file"]["key"]["k"],
                    event.source["content"]["file"]["hashes"]["sha256"],
                    event.source["content"]["file"]["iv"],
                )
            )
        await output_file.write(serialize_event(dict(type="media", src=filename,)))
    elif isinstance(event, RedactedEvent):
        await output_file.write(serialize_event(dict(type="redacted",)))


async def save_avatars(client: AsyncClient, room: MatrixRoom) -> None:
    avatar_dir = mkdir(f"{OUTPUT_DIR}/{room.display_name}_{room.room_id}_avatars")
    for user in room.users.values():
        if user.avatar_url:
            async with aiofiles.open(f"{avatar_dir}/{user.user_id}", "wb") as f:
                await f.write(await download_mxc(client, user.avatar_url))


async def download_mxc(client: AsyncClient, url: str):
    mxc = urlparse(url)
    response = await client.download(mxc.netloc, mxc.path.strip("/"))
    return response.body


async def fetch_room_events(
    client: AsyncClient,
    start_token: str,
    room: MatrixRoom,
    direction: MessageDirection,
) -> list:
    is_valid_event = lambda e: isinstance(
        e, (RoomMessageFormatted, RoomMessageMedia, RoomEncryptedMedia, RedactedEvent,)
    )
    events = []
    while True:
        response = await client.room_messages(
            room.room_id, start_token, limit=1000, direction=direction
        )
        if len(response.chunk) == 0:
            break
        events.extend(event for event in response.chunk if is_valid_event(event))
        start_token = response.end
    return events


async def main() -> None:
    try:
        client = await create_client()
        selected_rooms = set()
        while True:
            sync_resp = await client.sync(
                full_state=True, sync_filter={"room": {"timeline": {"limit": 1}}}
            )
            room = await select_room(client, selected_rooms)
            print("Fetching room messages and writing to disk...")
            start_token = sync_resp.rooms.join[room.room_id].timeline.prev_batch
            # Generally, it should only be necessary to fetch back events but,
            # sometimes depending on the sync, front events need to be fetched
            # as well.
            fetch_room_events_ = partial(fetch_room_events, client, start_token, room)
            async with aiofiles.open(
                f"{OUTPUT_DIR}/{room.display_name}_{room.room_id}.yaml", "w"
            ) as f:
                for events in [
                    reversed(await fetch_room_events_(MessageDirection.back)),
                    await fetch_room_events_(MessageDirection.front),
                ]:
                    for event in events:
                        try:
                            await write_event(client, room, f, event)
                        except exceptions.EncryptionError as e:
                            print(e)
            await save_avatars(client, room)
            print("Successfully wrote all events to disk.")
    except KeyboardInterrupt:
        sys.exit(1)
    finally:
        await client.logout()
        await client.close()


if __name__ == "__main__":
    ARGS = parse_args()
    OUTPUT_DIR = mkdir(ARGS.folder)
    asyncio.get_event_loop().run_until_complete(main())
