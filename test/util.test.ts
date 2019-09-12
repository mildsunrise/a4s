import { URLSearchParams, URL } from 'url'
import { formatHost, parseHost, DEFAULT_REGION } from '../src/util/endpoint'
import { toURL, getHeader, toRequestOptions } from '../src/util/request'

describe('request utilities', () => {
    it('getHeader works correctly', () => {
        expect(getHeader(undefined, 'naMe')).toStrictEqual(['name', undefined])
        expect(getHeader({ nAme: 2 }, 'naMe')).toStrictEqual(['nAme', '2'])
        expect(getHeader({ nAme: '' }, 'naMe')).toStrictEqual(['nAme', ''])
        expect(getHeader({ nAme: undefined }, 'naMe')).toStrictEqual(['nAme', 'undefined'])
        expect(getHeader({ nAme: ['a', 'b'] }, 'naMe')).toStrictEqual(['nAme', 'a,b'])
        expect(getHeader({ other: 2 }, 'naMe')).toStrictEqual(['name', undefined])
        expect(getHeader({}, 'naMe')).toStrictEqual(['name', undefined])
    })
    it('toRequestOptions works correctly', () => {
        const headers = { a: 1, b: 'm' }
        const result = toRequestOptions({
            url: {},
            headers,
            body: 'test',
        })
        expect(result).toStrictEqual({
            method: undefined,
            host: undefined,
            path: '/',
            headers,
        })
        expect(result.headers).toBe(headers)
        expect(toRequestOptions({
            method: 'PUT',
            url: { host: 'test1', searchParams: new URLSearchParams() },
            headers,
            body: 'test',
        })).toStrictEqual({ method: 'PUT', host: 'test1', path: '/', headers })
        expect(toRequestOptions({
            method: 'PUT',
            url: { host: 'test1', pathname: '/a b', searchParams: new URLSearchParams('m=2') },
            headers,
        })).toStrictEqual({ method: 'PUT', host: 'test1', path: '/a b?m=2', headers })
        expect(toRequestOptions({
            url: 'https://test/path?query=2',
            headers,
            body: 'test',
        })).toStrictEqual({ method: undefined, host: 'test', path: '/path?query=2', headers })
        expect(toRequestOptions({
            url: new URL('https://test/path?query=2'),
            headers,
            body: 'test',
        })).toStrictEqual({ method: undefined, host: 'test', path: '/path?query=2', headers })
    })
    it('toURL works correctly', () => {
        expect(toURL({
            host: 'test',
            pathname: '/c a//./b',
            searchParams: new URLSearchParams('m=2')
        })).toBe('https://test/c%20a//./b?m=2')
        expect(toURL({
            pathname: '/c a//./b',
            searchParams: new URLSearchParams('m=2')
        })).toBe('/c%20a//./b?m=2')
        expect(toURL({
            pathname: '/c a//./b',
        })).toBe('/c%20a//./b')
        expect(toURL({
            pathname: '/c a//./b',
            searchParams: new URLSearchParams()
        })).toBe('/c%20a//./b')
        expect(toURL({
            searchParams: new URLSearchParams()
        })).toBe('/')
        expect(toURL({
        })).toBe('/')
        expect(toURL({
            host: 'yeah'
        })).toBe('https://yeah/')
        expect(() => toURL({ pathname: 'test' })).toThrow()
        expect(toURL(new URL('http://test/path'))).toBe('http://test/path')
        expect(toURL('string returns unchanged')).toBe('string returns unchanged')
    })
})

describe('endpoint utilities', () => {
    it('throws when parsing an invalid string', () => {
        expect(() => parseHost('')).toThrow()
        expect(() => parseHost('ec2.amazonaws.co')).toThrow()
        expect(() => parseHost('ec2.amazonaws.co ')).toThrow()
    })
    it('parses basic endpoints, in both forms', () => {
        expect(parseHost('au-east-1.cognito.amazonaws.com'))
            .toStrictEqual({ serviceName: 'cognito', regionName: 'au-east-1' })
        expect(parseHost('cognito.au-east-1.amazonaws.com'))
            .toStrictEqual({ serviceName: 'cognito', regionName: 'au-east-1' })
    })
    it('ignores port number', () => {
        expect(parseHost('au-east-1.cognito.amazonaws.com:41'))
            .toStrictEqual({ serviceName: 'cognito', regionName: 'au-east-1' })
        expect(parseHost('cognito.au-east-1.amazonaws.com:41'))
            .toStrictEqual({ serviceName: 'cognito', regionName: 'au-east-1' })
    })
    it('defaults to DEFAULT_REGION if not present', () => {
        expect(parseHost('ec2.amazonaws.com'))
            .toStrictEqual({ serviceName: 'ec2', regionName: DEFAULT_REGION })
        expect(parseHost('subdomain.s3.amazonaws.com'))
            .toStrictEqual({ serviceName: 's3', regionName: DEFAULT_REGION })
    })
    it('parses uppercase well', () => {
        expect(parseHost('Us-weST-1.EC2.AmAZONAWS.com'))
            .toStrictEqual({ serviceName: 'ec2', regionName: 'us-west-1' })
    })
    it('parses .com.cn TLD correctly', () => {
        expect(parseHost('Us-weST-1.EC2.AmAZONAWS.com.cN'))
            .toStrictEqual({ serviceName: 'ec2', regionName: 'us-west-1' })
    })
    it('works with imaginary (or new) services', () => {
        expect(parseHost('au-east-1.pepper-fish.amazonaws.com'))
            .toStrictEqual({ serviceName: 'pepper-fish', regionName: 'au-east-1' })
        expect(parseHost('pepper-fish.au-east-1.amazonaws.com'))
            .toStrictEqual({ serviceName: 'pepper-fish', regionName: 'au-east-1' })
    })
    it('parses correctly with subdomains, in both forms', () => {
        expect(parseHost('sub.domain.ec2.amazonaws.com'))
            .toStrictEqual({ serviceName: 'ec2', regionName: DEFAULT_REGION })
        expect(parseHost('sub.domain.eu-east-1.ec2.amazonaws.com'))
            .toStrictEqual({ serviceName: 'ec2', regionName: 'eu-east-1' })
        expect(parseHost('sub.domain.ec2.eu-east-1.amazonaws.com'))
            .toStrictEqual({ serviceName: 'ec2', regionName: 'eu-east-1' })
    })
    it('parses S3-style endpoints', () => {
        expect(parseHost('s3-us-west-1.amazonaws.com'))
            .toStrictEqual({ serviceName: 's3', regionName: 'us-west-1' })
        expect(parseHost('bucket.s3-us-west-1.amazonaws.com'))
            .toStrictEqual({ serviceName: 's3', regionName: 'us-west-1' })
        expect(parseHost('s3.s3-us-west-1.amazonaws.com'))
            .toStrictEqual({ serviceName: 's3', regionName: 'us-west-1' })
        expect(parseHost('us-east-1.s3-us-west-1.amazonaws.com'))
            .toStrictEqual({ serviceName: 's3', regionName: 'us-west-1' })
    })
    it('parses -fips endpoints', () => {
        expect(parseHost('ec2-fips.us-west-1.amazonaws.com:80'))
            .toStrictEqual({ serviceName: 'ec2', regionName: 'us-west-1' })
    })
    it('formats an endpoint without region', () => {
        expect(formatHost('s3')).toBe('s3.amazonaws.com')
        expect(formatHost('s3', undefined, 1000)).toBe('s3.amazonaws.com:1000')
    })
    it('formats an endpoint with region', () => {
        expect(formatHost('s3', undefined, 1000)).toBe('s3.amazonaws.com:1000')
    })
    it('uses/detects correct domain for SES', () => {
        expect(parseHost('email.eu-west-1.amazonaws.com'))
            .toStrictEqual({ serviceName: 'ses', regionName: 'eu-west-1' })
        expect(formatHost('ses', 'eu-west-1'))
            .toStrictEqual('email.eu-west-1.amazonaws.com')
    })
})
