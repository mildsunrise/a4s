import { formatTimestamp, formatDate, getSigningData, signDigest } from '../src/core'

import * as crypto from 'crypto'
const hmac = jest.spyOn((crypto as any).Hmac.prototype, 'digest')

describe('Core signing', () => {

    it('generates timestamps correctly', () => {
        expect(formatTimestamp(new Date(1935346573456))).toBe('20310430T201613Z')
        expect(formatTimestamp()).toMatch(/^20\d{6}T\d{6}Z$/)
    })

    it('generates datestamps correctly', () => {
        expect(formatDate(new Date(1935346573456))).toBe('20310430')
        expect(formatDate()).toMatch(/^20\d{6}$/)
    })

    it('derives a key correctly', () => {
        expect(getSigningData('20310430', 'test', 'eu-west-3', 'service')).toStrictEqual(
            {
                scope: '20310430/eu-west-3/service/aws4_request',
                key: Buffer.from('674f7e8745f37c14fe188810745a0c54d78824d747e69eb74396c369ae5f7b4d', 'hex')
            }
        )
    })

    it('simple cache works correctly', () => {
        const derive: any = getSigningData.makeSimpleCache()
        const key1 = {
            date: '20310430',
            args: ['test', 'eu-west-3', 'service'],
            result: {
                scope: '20310430/eu-west-3/service/aws4_request',
                key: Buffer.from('674f7e8745f37c14fe188810745a0c54d78824d747e69eb74396c369ae5f7b4d', 'hex')
            }
        }
        const key2 = {
            date: '20310431',
            args: ['test', 'eu-west-3', 'service'],
            result: {
                scope: '20310431/eu-west-3/service/aws4_request',
                key: Buffer.from('2bcc47ebfe90545ac1b8c8fe9a76a8a4a066cbae64b8b57a27a74def2cf5bafe', 'hex')
            }
        }
        hmac.mockClear()
        expect(derive(key1.date + 'T101010Z', ...key1.args)).toStrictEqual(key1.result)
        expect(hmac).toHaveBeenCalled()
        hmac.mockClear()
        expect(derive(key1.date + 'T111111Z', ...key1.args)).toStrictEqual(key1.result)
        expect(hmac).not.toHaveBeenCalled()
        expect(derive(key2.date + 'T101010Z', ...key2.args)).toStrictEqual(key2.result)
        expect(derive(key1.date + 'T121212Z', ...key1.args)).toStrictEqual(key1.result)
        expect(derive(key2.date + 'T121212Z', ...key2.args)).toStrictEqual(key2.result)
        hmac.mockClear()
        expect(derive(key2.date + 'T111111Z', ...key2.args)).toStrictEqual(key2.result)
        expect(hmac).not.toHaveBeenCalled()
    })

    it('signs a payload digest correctly', () => {
        expect(signDigest(
            'ALG',
            '2e1cf7ed91881a30569e46552437e4156c823447bf1781b921b5d486c568dd1c',
            '20310430T201613Z',
            {
                scope: '20310430/eu-west-3/service/aws4_request',
                key: Buffer.from('674f7e8745f37c14fe188810745a0c54d78824d747e69eb74396c369ae5f7b4d', 'hex')
            },
        ).toString('hex')).toBe('f32bf1ce9850de71499f36962e445aba4ef65870af1688974b4f4426f685aac3')
    })

})
