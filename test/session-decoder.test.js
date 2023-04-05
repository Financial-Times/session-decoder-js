'use strict';

const chai = require('chai');
const expect = chai.expect;
const SessionDecoder = require('../src/session-decoder');
const publicKey = 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4U5p7RQ4YR89NPSuQFoNBaras4BSrBirYO1JzAnfVJr9FfEqpDyHiW1Vwg9RcYp7Uo7E_fE6Pq-3rb9lD6m6wA';
const decoder = new SessionDecoder(publicKey);

describe('SessionDecoder', () => {
	describe('#constructor', () => {
		it('should throw an error if no public key is provided', () => {
			expect(() => {
				new SessionDecoder(null);
			}).to.throw('missing public key in session token decoder constructor');
		});
	});

	describe('#decode', () => {
		it('should throw an error for invalid session format', () => {
			expect(() => {
				decoder.decode('invalid-format');
			}).to.throw('Invalid session - incorrect format');
		});

		it('should return a uuid from a valid session', () => {
			const sessionValue = 'z1hmrYYYPkZd05pFdLsDG1QKzwAAAVY2C673ww.MEQCICSwJIe5CUKslyxX4vlpPt2B0f9upZnX91QeVE9n1Jr9AiBB30Ry8QdYaMYg3Ns7wTZnBz8dIQ6OIr5UpNT3foliIw';
			const uuid = decoder.decode(sessionValue);
			expect(uuid).to.equal('5866ad86-183e-465d-9a45-74bb031b540a');
		});

		it('should throw an error for invalid session signature', () => {
			const sessionValue = 'Z1hmrYYYPkZd05pFdLsDG1QKzwAAAVY2C673ww.MEQCICSwJIe5CUKslyxX4vlpPt2B0f9upZnX91QeVE9n1Jr9AiBB30Ry8QdYaMYg3Ns7wTZnBz8dIQ6OIr5UpNT3foliIw';
			expect(() => {
				decoder.decode(sessionValue);
			}).to.throw('Invalid session - signature verification failed');
		});

		it('should throw an error for incorrect session signature', () => {
			const sessionValue = 'z1hmrYYYPkZd05pFdLsDG1QKzwAAAVY2C673ww.MEQCICSwJIe5CUKslyxX4vlpPt2B0f9upZnX91QeVE9n1Jr9AiBB30Ry8QdYaMYg3Ns7wTZnBz8dIQ6OIr5UpNT3foliIW';
			expect(() => {
				decoder.decode(sessionValue);
			}).to.throw('Invalid session - signature verification failed');
		});

		it('should throw an error for a modified session token', () => {
			const sessionValue = 'Z1hmrYYYPkZd05pFdLsDG1QKzwAAAVY2C673ww.MEQCICSwJIe5CUKslyxX4vlpPt2B0f9upZnX91QeVE9n1Jr9AiBB30Ry8QdYaMYg3Ns7wTZnBz8dIQ6OIr5UpNT3foliIw';
			const modifiedSessionValue = sessionValue.replace(/y/g, 'z');

			expect(() => {
				decoder.decode(modifiedSessionValue);
			}).to.throw('Invalid session - signature verification failed');
		});
		it('should throw PEM read error if public key is bad', () => {
			expect(() => {
				new SessionDecoder('someBadPublicKey')
					.decode('z1hmrYYYPkZd05pFdLsDG1QKzwAAAVY2C673ww.MEQCICSwJIe5CUKslyxX4vlpPt2B0f9upZnX91QeVE9n1Jr9AiBB30Ry8QdYaMYg3Ns7wTZnBz8dIQ6OIr5UpNT3foliIw');
			}).to.throw(/(PEM_read_bio_PUBKEY|header too long)/);
		});

	})
	});
