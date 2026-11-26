"""Assign or rotate an ordinary member PIN from the database operator's console."""

import asyncio
import getpass

import asyncpg
from passlib.hash import argon2

from member_api import PAN, PIN, active_card, ordinary


async def provision(pan, pin):
    db = await asyncpg.connect(database='shadybucks')
    try:
        async with db.transaction():
            card = await db.fetchrow(
                'SELECT c.account_id,c.status,c.expires,a.partner,a.admin,a.special '
                'FROM cards c JOIN accounts a ON a.id=c.account_id WHERE c.pan=$1 FOR UPDATE OF a,c',pan)
            if not ordinary(card) or not active_card(card):
                raise ValueError('Eligible member card required')
            digest = await asyncio.get_running_loop().run_in_executor(None, argon2.hash, pin)
            await db.execute("DELETE FROM secrets WHERE account_id=$1 AND type='pin'",card['account_id'])
            await db.execute("INSERT INTO secrets(account_id,type,secret) VALUES($1,'pin',$2)",card['account_id'],digest)
    finally:
        await db.close()


def main():
    pan = getpass.getpass('Member card number: ')
    pin = getpass.getpass('New assigned member PIN (4-8 digits): ')
    confirm = getpass.getpass('Confirm PIN: ')
    if not PAN.fullmatch(pan) or not PIN.fullmatch(pin) or pin != confirm:
        raise SystemExit('Invalid number, PIN or confirmation.')
    try:
        asyncio.run(provision(pan,pin))
    except ValueError:
        raise SystemExit('Eligible member card required.')
    print('Member PIN assigned.')


if __name__ == '__main__':
    main()
