'use strict';

module.exports = {
  mock: function () {
    var documentNode = {
      $: jasmine.createSpy(),
      delete: jasmine.createSpy(),
      getDocument: jasmine.createSpy(),
      setDocument: jasmine.createSpy(),
      increment: jasmine.createSpy(),
      forEachChild: jasmine.createSpy(),
      lock: jasmine.createSpy(),
      unlock: jasmine.createSpy(),
      value: jasmine.createSpy()
    };

    return documentNode;
  }
};
